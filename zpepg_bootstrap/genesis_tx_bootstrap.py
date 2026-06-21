"""
ZPEPG Bootstrap - Genesis transaction construction.

Builds, signs, and submits the one-time genesis bootstrap transaction:
spend the genesis UTXO, mint exactly 1 beacon token under the
now-parameterized beacon_policy, and create the very first
archive_registry master UTXO carrying the beacon + a fully-initialized
MasterDatum.

This mirrors the manual script's structure exactly (per the decision to
follow the already-verified-on-chain manual flow rather than deviate),
with one structural difference: instead of importing pccontext's
YaciDevkitChainContext and monkeypatching around its confirmed bugs
(missing last_block_slot, broken protocol_param/evaluate_tx_cbor/
submit_tx_cbor/utxos), this defines a minimal ChainContext subclass here
that is backed by our own already-tested ChainProvider from provider.py
from the start. Same underlying REST calls and wire-format workarounds
the manual script confirmed necessary - just implemented as the real
thing rather than patched onto a buggy base class.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Union

from pycardano import (
    Address,
    Asset,
    AssetName,
    MultiAsset,
    Network,
    PaymentExtendedSigningKey,
    PlutusV3Script,
    ProtocolParameters,
    Redeemer,
    ScriptHash,
    TransactionBuilder,
    TransactionId,
    TransactionInput,
    TransactionOutput,
    UTxO,
    Value,
)
from pycardano.backend.base import ChainContext
from pycardano.plutus import ExecutionUnits

from zpepg_bootstrap.provider import ChainProvider, ProviderError, UtxoInfo
from zpepg_bootstrap.perm_keys import PermKeySet
from zpepg_bootstrap.wallet import DerivedAccount
from zpepg_bootstrap.zpepg_types import (
    AikenFalse,
    InlineStakeCredential,
    MasterDatum,
    MintBeacon,
    NoneChainLink,
    OutputReference,
    PlutusAddress,
    RegistryStats,
    SomeStakeCredential,
    VerificationKeyCredential,
)

# Min-UTXO ADA to send with the master UTXO. The manual script used
# 3_000_000 lovelace; kept identical since that value was confirmed
# sufficient on-chain for this datum's size.
MASTER_UTXO_LOVELACE = 3_000_000

# Generous buffer added to current tip slot for the tx's TTL. Matches the
# manual script's value; devnet blocks are ~1s each so this is generous
# there, but should be reconsidered for preview/preprod/mainnet where
# slot timing differs.
TTL_BUFFER_SLOTS = 200


class GenesisTxError(Exception):
    """Raised for any failure while building, signing, or submitting the
    genesis transaction."""


class ProviderBackedChainContext(ChainContext):
    """Minimal pycardano ChainContext, backed entirely by our own
    ChainProvider. Implements only what TransactionBuilder actually
    touches (confirmed by inspecting pycardano 0.19.2's TransactionBuilder
    source: evaluate_tx, last_block_slot, network, protocol_param, utxos),
    rather than the full ChainContext surface."""

    def __init__(self, provider: ChainProvider, network: Network):
        self._provider = provider
        self._network = network
        self._cached_protocol_param: ProtocolParameters | None = None

    @property
    def network(self) -> Network:
        return self._network

    @property
    def protocol_param(self) -> ProtocolParameters:
        if self._cached_protocol_param is None:
            try:
                self._cached_protocol_param = self._provider.protocol_parameters()
            except ProviderError as e:
                raise GenesisTxError(f"Could not fetch protocol parameters: {e}") from e
        return self._cached_protocol_param

    @property
    def last_block_slot(self) -> int:
        try:
            return self._provider.current_slot()
        except ProviderError as e:
            raise GenesisTxError(f"Could not fetch current slot: {e}") from e

    def utxos(self, address: Union[str, Address]) -> list[UTxO]:
        addr_str = str(address)
        try:
            provider_utxos = self._provider.get_utxos(addr_str)
        except ProviderError as e:
            raise GenesisTxError(f"Could not fetch UTXOs for {addr_str}: {e}") from e

        results: list[UTxO] = []
        for u in provider_utxos:
            tx_input = TransactionInput(
                transaction_id=TransactionId(bytes.fromhex(u.tx_hash)),
                index=u.output_index,
            )
            multi_asset = MultiAsset({})
            if u.assets:
                grouped: dict[bytes, dict[bytes, int]] = {}
                for asset in u.assets:
                    policy_hex, _, asset_name_hex = asset.unit.partition(".")
                    policy_bytes = bytes.fromhex(policy_hex)
                    asset_name_bytes = bytes.fromhex(asset_name_hex) if asset_name_hex else b""
                    grouped.setdefault(policy_bytes, {})[asset_name_bytes] = asset.quantity
                multi_asset = MultiAsset(
                    {
                        ScriptHash(policy): Asset(
                            {AssetName(name): qty for name, qty in names.items()}
                        )
                        for policy, names in grouped.items()
                    }
                )

            tx_output = TransactionOutput(
                address=Address.from_primitive(u.address),
                amount=Value(coin=u.lovelace, multi_asset=multi_asset),
            )
            results.append(UTxO(input=tx_input, output=tx_output))

        return results

    def evaluate_tx_cbor(self, cbor: Union[bytes, str]) -> dict[str, ExecutionUnits]:
        cbor_bytes = bytes.fromhex(cbor) if isinstance(cbor, str) else cbor
        try:
            return self._provider.evaluate_tx(cbor_bytes)
        except ProviderError as e:
            raise GenesisTxError(f"Transaction evaluation failed: {e}") from e

    def submit_tx_cbor(self, cbor: Union[bytes, str]) -> None:
        cbor_bytes = bytes.fromhex(cbor) if isinstance(cbor, str) else cbor
        try:
            self._provider.submit_tx(cbor_bytes)
        except ProviderError as e:
            raise GenesisTxError(f"Transaction submission failed: {e}") from e

    # genesis_param / epoch are part of the abstract ChainContext surface
    # but are NOT touched by TransactionBuilder.build() (confirmed by
    # source inspection) and are not needed anywhere in bootstrap. They
    # are intentionally left unimplemented (will raise NotImplementedError
    # from the base class) rather than stubbed with fake values, so any
    # accidental future dependency on them fails loudly instead of
    # silently returning nonsense.


def _require_32_bytes(name: str, value: bytes) -> bytes:
    if len(value) != 32:
        raise GenesisTxError(
            f"{name} must be exactly 32 bytes for an Ed25519 verification "
            f"key, got {len(value)} bytes. This usually means perm_keys.json "
            f"contains a malformed or non-raw-key value."
        )
    return value


def build_owner_plutus_address(account: DerivedAccount) -> PlutusAddress:
    """Build the Plutus-level Address for MasterDatum.owner_address from
    the funding/owner wallet's derived keys. Mirrors the manual script's
    construction exactly: Some(Inline(VKCred(payment_hash))) for stake,
    VKCred(payment_hash) for payment."""
    payment_hash = bytes(account.payment_verification_key.hash())
    staking_hash = bytes(account.stake_verification_key.hash())

    return PlutusAddress(
        payment_credential=VerificationKeyCredential(payment_hash),
        stake_credential=SomeStakeCredential(
            InlineStakeCredential(VerificationKeyCredential(staking_hash))
        ),
    )


def build_genesis_master_datum(
    perm_keys: PermKeySet,
    owner_address: PlutusAddress,
    registry_policy_id: bytes,
    asset_name_prefix: bytes,
    beacon_policy_id: bytes,
    beacon_asset_name: bytes,
) -> MasterDatum:
    """Build the genesis MasterDatum: nonce=0, zeroed stats, no chain
    links yet, beacon identity baked in. Mirrors the manual script's
    genesis_master_datum construction."""
    authority_key = _require_32_bytes("authority_key", perm_keys.authority.public_key_bytes)
    operator_key = _require_32_bytes("operator_key", perm_keys.operator.public_key_bytes)
    owner_key = _require_32_bytes("owner_key", perm_keys.owner.public_key_bytes)

    return MasterDatum(
        authority_key=authority_key,
        operator_key=operator_key,
        owner_key=owner_key,
        owner_address=owner_address,
        nonce=0,
        is_paused=AikenFalse(),
        policy_id=registry_policy_id,
        asset_name_prefix=asset_name_prefix,
        beacon_policy_id=beacon_policy_id,
        beacon_asset_name=beacon_asset_name,
        forward_link=NoneChainLink(),
        backward_link=NoneChainLink(),
        stats=RegistryStats(
            total_token_count=0,
            total_unique_documents=0,
            last_minted_at=0,
            last_cross_chain_global_id=b"",
            last_cardano_asset_id=b"",
        ),
    )


@dataclass(frozen=True)
class GenesisTxResult:
    tx_id: str
    master_utxo_ref: str  # "<tx_id>#0"
    registry_script_address: str
    registry_policy_id_hex: str
    beacon_policy_id_hex: str
    beacon_asset_name_hex: str


def run_genesis_transaction(
    provider: ChainProvider,
    network: Network,
    funding_account: DerivedAccount,
    genesis_utxo: UtxoInfo,
    beacon_compiled_code_hex: str,
    beacon_policy_id_hex: str,
    beacon_asset_name: bytes,
    registry_compiled_code_hex: str,
    registry_policy_id_hex: str,
    asset_name_prefix: bytes,
    perm_keys: PermKeySet,
) -> GenesisTxResult:
    """
    Build, sign, and submit the genesis bootstrap transaction. Mirrors the
    manual script's structure step for step:
      1. Confirm genesis UTXO is spendable as an input
      2. Beacon mint redeemer = MintBeacon()
      3. owner_address built from funding_account's own keys
      4. genesis MasterDatum (nonce=0, zeroed stats, beacon identity baked in)
      5. Build tx: spend genesis input, mint 1 beacon, create master output
      6. Sign with funding_account's payment key, submit
    """
    context = ProviderBackedChainContext(provider, network)

    registry_policy_id_bytes = bytes.fromhex(registry_policy_id_hex)
    registry_script_address = Address(
        payment_part=ScriptHash(registry_policy_id_bytes),
        network=network,
    )

    beacon_policy_id_bytes = bytes.fromhex(beacon_policy_id_hex)
    beacon_script = PlutusV3Script(bytes.fromhex(beacon_compiled_code_hex))

    genesis_ref_input = TransactionInput(
        transaction_id=TransactionId(bytes.fromhex(genesis_utxo.tx_hash)),
        index=genesis_utxo.output_index,
    )
    genesis_utxo_obj = UTxO(
        input=genesis_ref_input,
        output=TransactionOutput(
            address=Address.from_primitive(genesis_utxo.address),
            amount=Value(coin=genesis_utxo.lovelace),
        ),
    )

    owner_plutus_address = build_owner_plutus_address(funding_account)

    genesis_master_datum = build_genesis_master_datum(
        perm_keys=perm_keys,
        owner_address=owner_plutus_address,
        registry_policy_id=registry_policy_id_bytes,
        asset_name_prefix=asset_name_prefix,
        beacon_policy_id=beacon_policy_id_bytes,
        beacon_asset_name=beacon_asset_name,
    )

    try:
        current_slot = context.last_block_slot
    except GenesisTxError:
        raise

    builder = TransactionBuilder(context, ttl=current_slot + TTL_BUFFER_SLOTS)
    builder.add_input(genesis_utxo_obj)
    builder.add_minting_script(beacon_script, Redeemer(MintBeacon()))

    beacon_multi_asset = MultiAsset(
        {ScriptHash(beacon_policy_id_bytes): Asset({AssetName(beacon_asset_name): 1})}
    )
    builder.mint = beacon_multi_asset

    master_output = TransactionOutput(
        address=registry_script_address,
        amount=Value(coin=MASTER_UTXO_LOVELACE, multi_asset=beacon_multi_asset),
        datum=genesis_master_datum,
    )
    builder.add_output(master_output)

    try:
        signed_tx = builder.build_and_sign(
            signing_keys=[funding_account.payment_signing_key],
            change_address=funding_account.address,
        )
    except Exception as e:
        raise GenesisTxError(f"Failed to build/sign genesis transaction: {e}") from e

    try:
        context.submit_tx(signed_tx)
    except GenesisTxError:
        raise
    except Exception as e:
        raise GenesisTxError(f"Failed to submit genesis transaction: {e}") from e

    tx_id_str = str(signed_tx.id)

    return GenesisTxResult(
        tx_id=tx_id_str,
        master_utxo_ref=f"{tx_id_str}#0",
        registry_script_address=str(registry_script_address),
        registry_policy_id_hex=registry_policy_id_hex,
        beacon_policy_id_hex=beacon_policy_id_hex,
        beacon_asset_name_hex=beacon_asset_name.hex(),
    )