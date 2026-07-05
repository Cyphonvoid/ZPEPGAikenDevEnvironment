"""
cardano_workflow.py - ZPEPG deployment workflow components.

All classes here are namespace classes (no instantiation needed) except
where a real instance is necessary. Each class owns its own constants,
error types, and logic. Nothing in this file does input-gathering,
prompting, or CLI argument parsing - that lives in cardano_deploy.py.

SINGLE-SCRIPT ARCHITECTURE: this version replaces the prior two-stage
deployment (compile beacon_contract.ak first, learn its policy ID, THEN
compile registry_contract.ak parameterized by that policy ID) with a
single compiled artifact. registry_contract.ak's `validator
archive_registry(genesis_ref: OutputReference, beacon_asset_name:
ByteArray)` is parameterized directly by the genesis UTXO and the chosen
beacon asset name, and its `mint` entrypoint's MintBeacon redeemer
performs what beacon_contract.ak used to do standalone. Since spend and
mint are both declared inside the same validator block, they compile to
ONE shared script hash - there is now exactly one policy ID for the
entire deployment, used as both the registry's script address and the
beacon's minting policy.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from fractions import Fraction
from pathlib import Path
from typing import Union

import bech32
import cbor2

from pycardano import (
    Address, Asset, AssetName, MultiAsset, Network,
    PaymentExtendedSigningKey, PaymentVerificationKey,
    PlutusV3Script, ProtocolParameters,
    Redeemer, ScriptHash, StakeExtendedSigningKey, StakeVerificationKey,
    TransactionBuilder, TransactionId, TransactionInput,
    TransactionOutput, UTxO, Value, HDWallet,
)
from pycardano.backend.base import ChainContext
from pycardano.plutus import ExecutionUnits


try:
    from CardanoDeployer.cardano_types import (
        AikenFalse, InlineStakeCredential, MasterDatum, MintBeacon,
        NoneChainLink, OutputReference, PlutusAddress, RegistryStats,
        SomeStakeCredential, VerificationKeyCredential,
    )
    from CardanoDeployer.cardano_network import NetworkBackend, NetworkError, UtxoInfo

except ImportError:
    # For local dev/test runs where the package isn't installed yet
    """from cardano_types import (
        AikenFalse, InlineStakeCredential, MasterDatum, MintBeacon,
        NoneChainLink, OutputReference, PlutusAddress, RegistryStats,
        SomeStakeCredential, VerificationKeyCredential,
    )
    from cardano_network import NetworkBackend, NetworkError, UtxoInfo"""

    
# ═══════════════════════════════════════════════════════════════════════════
# Wallet - mnemonic derivation, address scanning and verification
# ═══════════════════════════════════════════════════════════════════════════
# UNCHANGED from the two-script version - wallet derivation has no
# dependency on contract architecture.

class Wallet:
    """
    Namespace for mnemonic-based wallet derivation and address verification.

    Users know their address, not their derivation account index. resolve()
    scans a range of indices, derives the address at each, and finds which
    one matches the supplied address - so the index never needs to be
    known or supplied externally.
    """

    PURPOSE = 1852
    COIN_TYPE = 1815
    PAYMENT_ROLE = 0
    STAKE_ROLE = 2
    ADDRESS_INDEX = 0
    DEFAULT_SCAN_RANGE = range(0, 20)

    class NotFoundError(Exception):
        def __init__(self, address: str, scan_range: range):
            self.address = address
            self.scan_range = scan_range
            super().__init__(
                f"Address {address!r} not found in derivation range "
                f"{scan_range.start}-{scan_range.stop - 1} for the given mnemonic. "
                f"Check the address/mnemonic, or pass a wider scan_range."
            )

    @dataclass(frozen=True)
    class DerivedAccount:
        account_index: int
        payment_signing_key: PaymentExtendedSigningKey
        payment_verification_key: PaymentVerificationKey
        stake_signing_key: StakeExtendedSigningKey
        stake_verification_key: StakeVerificationKey
        address: Address

        def __repr__(self) -> str:
            # Deliberately omit signing keys from repr
            return f"DerivedAccount(index={self.account_index}, address={self.address})"

    @classmethod
    def derive_account(cls, hdwallet: HDWallet, account_index: int, network: Network) -> "Wallet.DerivedAccount":
        payment_path = f"m/{cls.PURPOSE}'/{cls.COIN_TYPE}'/{account_index}'/{cls.PAYMENT_ROLE}/{cls.ADDRESS_INDEX}"
        stake_path   = f"m/{cls.PURPOSE}'/{cls.COIN_TYPE}'/{account_index}'/{cls.STAKE_ROLE}/{cls.ADDRESS_INDEX}"

        p_hd  = hdwallet.derive_from_path(payment_path)
        p_esk = PaymentExtendedSigningKey.from_hdwallet(p_hd)
        p_evk = p_esk.to_verification_key()

        s_hd  = hdwallet.derive_from_path(stake_path)
        s_esk = StakeExtendedSigningKey.from_hdwallet(s_hd)
        s_evk = s_esk.to_verification_key()

        address = Address(
            payment_part=p_evk.hash(),
            staking_part=s_evk.hash(),
            network=network,
        )
        return Wallet.DerivedAccount(
            account_index=account_index,
            payment_signing_key=p_esk,
            payment_verification_key=p_evk,
            stake_signing_key=s_esk,
            stake_verification_key=s_evk,
            address=address,
        )

    @classmethod
    def resolve(
        cls,
        mnemonic: str,
        expected_address: str,
        network: Network,
        scan_range: range = None,
    ) -> "Wallet.DerivedAccount":
        if scan_range is None:
            scan_range = cls.DEFAULT_SCAN_RANGE

        hdwallet = HDWallet.from_mnemonic(mnemonic)
        target = Address.from_primitive(expected_address)

        if target.network != network:
            raise ValueError(
                f"Address is on network {target.network}, bootstrap is targeting {network}."
            )

        for idx in scan_range:
            candidate = cls.derive_account(hdwallet, idx, network)
            if candidate.address == target:
                return candidate

        raise Wallet.NotFoundError(expected_address, scan_range)


# ═══════════════════════════════════════════════════════════════════════════
# PermKeys - permission key set loading from perm_keys.json
# ═══════════════════════════════════════════════════════════════════════════
# UNCHANGED from the two-script version.

class PermKeys:
    """
    Namespace for loading and validating perm_keys.json.

    The permission key set (authority/operator/owner) is separate from the
    funding wallet. These are bare Ed25519 keypairs baked into MasterDatum
    as VerificationKeys, checked on-chain via verify_ed25519_signature for
    future redeemer actions (RotateKey, Pause, MintDocument, etc.).

    Bootstrap only needs the PUBLIC halves. Private keys are validated for
    structural correctness then immediately discarded - never logged, never
    persisted, never passed downstream.
    """

    REQUIRED_ROLES = ("authority", "operator", "owner")
    REQUIRED_FIELDS = ("private_key_hex", "public_key_hex")
    KEY_LENGTH_BYTES = 32

    EXAMPLE_STRUCTURE = """{
        "authority": {
            "private_key_hex": "<64 hex chars>",
            "public_key_hex":  "<64 hex chars>"
        },
        "operator": {
            "private_key_hex": "<64 hex chars>",
            "public_key_hex":  "<64 hex chars>"
        },
        "owner": {
            "private_key_hex": "<64 hex chars>",
            "public_key_hex":  "<64 hex chars>"
        }
    }"""

    class Error(Exception):
        def __init__(self, reason: str):
            super().__init__(
                f"{reason}\n\n"
                f"perm_keys.json must have this structure:\n\n"
                f"{PermKeys.EXAMPLE_STRUCTURE}"
            )

    @dataclass(frozen=True)
    class KeySet:
        """Public-only view. Safe to log, embed in deployment.json, pass anywhere."""
        authority_key: bytes
        operator_key: bytes
        owner_key: bytes

        def as_dict(self) -> dict[str, str]:
            return {
                "authority_key": self.authority_key.hex(),
                "operator_key":  self.operator_key.hex(),
                "owner_key":     self.owner_key.hex(),
            }

    @classmethod
    def _validate_hex(cls, role: str, field: str, value) -> bytes:
        if not isinstance(value, str):
            raise PermKeys.Error(f"'{role}.{field}' must be a hex string, got {type(value).__name__}.")
        try:
            raw = bytes.fromhex(value)
        except ValueError as e:
            raise PermKeys.Error(f"'{role}.{field}' is not valid hex: {e}") from e
        if len(raw) != cls.KEY_LENGTH_BYTES:
            raise PermKeys.Error(
                f"'{role}.{field}' must be {cls.KEY_LENGTH_BYTES} bytes "
                f"({cls.KEY_LENGTH_BYTES * 2} hex chars), got {len(raw)}."
            )
        return raw

    @classmethod
    def load(cls, path: str | Path) -> "PermKeys.KeySet":
        path = Path(path)
        if not path.exists():
            raise PermKeys.Error(f"perm_keys.json not found at: {path}")
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            raise PermKeys.Error(f"perm_keys.json is not valid JSON: {e}") from e
        if not isinstance(data, dict):
            raise PermKeys.Error(f"perm_keys.json must be a JSON object, got {type(data).__name__}.")

        missing = [r for r in cls.REQUIRED_ROLES if r not in data]
        if missing:
            raise PermKeys.Error(f"perm_keys.json missing role(s): {', '.join(missing)}")

        public_keys = {}
        for role in cls.REQUIRED_ROLES:
            role_data = data[role]
            if not isinstance(role_data, dict):
                raise PermKeys.Error(f"'{role}' must be an object, got {type(role_data).__name__}.")
            missing_fields = [f for f in cls.REQUIRED_FIELDS if f not in role_data]
            if missing_fields:
                raise PermKeys.Error(f"'{role}' missing field(s): {', '.join(missing_fields)}")
            # Validate private key structure then discard immediately
            cls._validate_hex(role, "private_key_hex", role_data["private_key_hex"])
            del role_data
            # Only retain the public key
            public_keys[role] = cls._validate_hex(role, "public_key_hex", data[role]["public_key_hex"])

        return PermKeys.KeySet(
            authority_key=public_keys["authority"],
            operator_key=public_keys["operator"],
            owner_key=public_keys["owner"],
        )


# ═══════════════════════════════════════════════════════════════════════════
# AikenBlueprint - single-script two-parameter application via aiken CLI
# ═══════════════════════════════════════════════════════════════════════════

class AikenBlueprint:
    """
    Namespace for aiken blueprint apply subprocess calls.

    Shells out to the aiken CLI rather than reimplementing UPLC term
    application in Python - the CLI is the reference implementation and
    is already confirmed working manually. Any reimplementation risks
    subtly wrong UPLC application that silently binds to the wrong UTXO.

    `aiken blueprint apply` applies exactly ONE parameter per invocation,
    in the validator's declared parameter order. archive_registry now
    declares TWO parameters - `validator archive_registry(genesis_ref:
    OutputReference, beacon_asset_name: ByteArray)` - so this requires two
    sequential calls: apply genesis_ref to the raw blueprint, then apply
    beacon_asset_name to THAT output, producing the final fully-applied
    blueprint.

    CAVEAT (unverified against a live aiken invocation - confirm before
    trusting in a real deployment): genesis_ref's CBOR encoding was
    already confirmed working in the prior two-script version (it's a
    PlutusData record, encoded via OutputReference.to_cbor_hex()).
    beacon_asset_name's CBOR encoding here uses cbor2.dumps() directly on
    the raw bytes, which is the correct CBOR major-type-2 bytestring
    encoding for a Plutus Data ByteArray value - but this specific
    parameter-application path (a bare ByteArray, not a PlutusData record)
    hasn't been exercised against the actual aiken CLI yet in this
    project. Run `aiken blueprint apply --help` and a manual test apply
    against a throwaway blueprint to confirm before relying on this in a
    real deployment.
    """

    MODULE    = "registry_contract"
    VALIDATOR = "archive_registry"
    SPEND_TITLE = "registry_contract.archive_registry.spend"
    MINT_TITLE  = "registry_contract.archive_registry.mint"

    class Error(Exception):
        pass

    @dataclass(frozen=True)
    class AppliedScript:
        policy_id_hex: str          # shared by spend address AND beacon/registry minting policy
        compiled_code_hex: str      # identical for both spend and mint entries - same combined script
        blueprint_path: Path

    @classmethod
    def _require_aiken(cls) -> str:
        binary = shutil.which("aiken")
        if binary is None:
            raise AikenBlueprint.Error(
                "`aiken` CLI not found on PATH. Install Aiken and confirm "
                "`aiken --version` works before retrying."
            )
        return binary

    @classmethod
    def _find_validator(cls, blueprint: dict, title: str) -> dict | None:
        return next((v for v in blueprint.get("validators", []) if v.get("title") == title), None)

    @classmethod
    def _run_apply(cls, aiken: str, source: Path, output: Path, param_cbor_hex: str) -> None:
        cmd = [
            aiken, "blueprint", "apply",
            "-m", cls.MODULE,
            "-v", cls.VALIDATOR,
            "-i", str(source),
            "-o", str(output),
            param_cbor_hex,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired as e:
            raise AikenBlueprint.Error("`aiken blueprint apply` timed out.") from e
        except OSError as e:
            raise AikenBlueprint.Error(f"Failed to invoke aiken: {e}") from e

        if result.returncode != 0:
            raise AikenBlueprint.Error(
                f"`aiken blueprint apply` failed (exit {result.returncode}).\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )
        if not output.exists():
            raise AikenBlueprint.Error(
                f"`aiken blueprint apply` succeeded but output file not found: {output}"
            )

    @classmethod
    def apply_parameters(
        cls,
        genesis_ref: OutputReference,
        beacon_asset_name: bytes,
        source_blueprint_path: str | Path,
        output_blueprint_path: str | Path,
    ) -> "AikenBlueprint.AppliedScript":
        aiken = cls._require_aiken()
        source = Path(source_blueprint_path)
        output = Path(output_blueprint_path)

        if not source.exists():
            raise AikenBlueprint.Error(f"Source blueprint not found: {source}")

        intermediate = output.with_suffix(output.suffix + ".step1")

        # Step 1: apply genesis_ref (first declared parameter)
        cls._run_apply(aiken, source, intermediate, genesis_ref.to_cbor_hex())

        # Step 2: apply beacon_asset_name (second declared parameter),
        # against step 1's output, producing the final blueprint.
        beacon_asset_name_cbor_hex = cbor2.dumps(beacon_asset_name).hex()
        cls._run_apply(aiken, intermediate, output, beacon_asset_name_cbor_hex)

        try:
            intermediate.unlink()
        except OSError:
            pass  # cosmetic cleanup only, not load-bearing

        try:
            blueprint = json.loads(output.read_text())
        except json.JSONDecodeError as e:
            raise AikenBlueprint.Error(f"Output blueprint is not valid JSON: {e}") from e

        spend_validator = cls._find_validator(blueprint, cls.SPEND_TITLE)
        mint_validator = cls._find_validator(blueprint, cls.MINT_TITLE)
        if spend_validator is None or mint_validator is None:
            available = [v.get("title") for v in blueprint.get("validators", [])]
            raise AikenBlueprint.Error(
                f"Expected both '{cls.SPEND_TITLE}' and '{cls.MINT_TITLE}' in output "
                f"blueprint. Available: {available}"
            )
        if spend_validator["hash"] != mint_validator["hash"]:
            # Should be structurally impossible (same validator block, same
            # compiled script) - if this ever fires, something is deeply
            # wrong with the apply sequence or the source blueprint.
            raise AikenBlueprint.Error(
                f"spend hash ({spend_validator['hash']}) and mint hash "
                f"({mint_validator['hash']}) differ after parameter application - "
                f"expected identical, since both purposes share one compiled script."
            )

        return AikenBlueprint.AppliedScript(
            policy_id_hex=spend_validator["hash"],
            compiled_code_hex=spend_validator["compiledCode"],
            blueprint_path=output,
        )


# ═══════════════════════════════════════════════════════════════════════════
# GenesisTransaction - builds, signs, and submits the genesis tx
# ═══════════════════════════════════════════════════════════════════════════

class GenesisTransaction:
    """
    Namespace for building and submitting the one-time genesis bootstrap
    transaction. Owns a minimal ChainContext subclass backed by NetworkBackend
    rather than using pccontext (which has confirmed bugs in this project).

    SIMPLIFIED (single-script): genesis is now ONE step instead of two
    coordinated stages. Spend genesis_ref (a normal wallet-key-locked
    UTXO - its owner's signature on that input IS the authorization, no
    separate authority-key signature is needed for the one-shot beacon
    mint itself), mint the beacon under this script's own policy via the
    MintBeacon redeemer, and send the resulting output directly to this
    script's own address carrying the initial MasterDatum. The spend
    validator is never invoked during genesis, since nothing is being
    spent FROM the script yet at this point - only mint() fires.
    """

    MASTER_UTXO_LOVELACE = 3_000_000  # confirmed sufficient on-chain
    TTL_BUFFER_SLOTS     = 200        # generous buffer; adjust for mainnet

    class Error(Exception):
        pass

    @dataclass(frozen=True)
    class Result:
        tx_id: str
        master_utxo_ref: str
        registry_script_address: str
        policy_id_hex: str           # shared: registry's own policy AND beacon's policy
        beacon_asset_name_hex: str

    # ── Minimal ChainContext backed by NetworkBackend ──────────────────────
    # UNCHANGED from the two-script version.

    class _ProviderContext(ChainContext):
        """
        Implements only what TransactionBuilder actually calls
        (confirmed by source inspection of pycardano 0.19.2):
        evaluate_tx, last_block_slot, network, protocol_param, utxos.
        """

        def __init__(self, backend: NetworkBackend, network: Network):
            self._backend = backend
            self._network = network
            self._cached_params: ProtocolParameters | None = None

        @property
        def network(self) -> Network:
            return self._network

        @property
        def protocol_param(self) -> ProtocolParameters:
            if self._cached_params is None:
                try:
                    self._cached_params = self._backend.protocol_parameters()
                except NetworkError as e:
                    raise GenesisTransaction.Error(f"Could not fetch protocol parameters: {e}") from e
            return self._cached_params

        @property
        def last_block_slot(self) -> int:
            try:
                return self._backend.current_slot()
            except NetworkError as e:
                raise GenesisTransaction.Error(f"Could not fetch current slot: {e}") from e

        def utxos(self, address) -> list[UTxO]:
            addr_str = str(address)
            try:
                provider_utxos = self._backend.get_utxos(addr_str)
            except NetworkError as e:
                raise GenesisTransaction.Error(f"Could not fetch UTXOs for {addr_str}: {e}") from e

            results = []
            for u in provider_utxos:
                tx_input = TransactionInput(
                    transaction_id=TransactionId(bytes.fromhex(u.tx_hash)),
                    index=u.output_index,
                )
                multi_asset = MultiAsset({})
                if u.assets:
                    # NOTE: unit strings from the provider have NO separator
                    # between policy_id and asset_name (confirmed against
                    # real devnet data). policy_id is always exactly 56 hex
                    # chars (28 bytes); everything after that is the
                    # asset_name.
                    POLICY_ID_HEX_LEN = 56
                    grouped: dict[bytes, dict[bytes, int]] = {}
                    for asset in u.assets:
                        policy_hex = asset.unit[:POLICY_ID_HEX_LEN]
                        name_hex = asset.unit[POLICY_ID_HEX_LEN:]
                        p = bytes.fromhex(policy_hex)
                        n = bytes.fromhex(name_hex) if name_hex else b""
                        grouped.setdefault(p, {})[n] = asset.quantity
                    multi_asset = MultiAsset({
                        ScriptHash(p): Asset({AssetName(n): q for n, q in names.items()})
                        for p, names in grouped.items()
                    })
                tx_output = TransactionOutput(
                    address=Address.from_primitive(u.address),
                    amount=Value(coin=u.lovelace, multi_asset=multi_asset),
                )
                results.append(UTxO(input=tx_input, output=tx_output))
            return results

        def evaluate_tx_cbor(self, cbor) -> dict[str, ExecutionUnits]:
            cbor_bytes = bytes.fromhex(cbor) if isinstance(cbor, str) else cbor
            try:
                return self._backend.evaluate_tx(cbor_bytes)
            except NetworkError as e:
                raise GenesisTransaction.Error(f"Transaction evaluation failed: {e}") from e

        def submit_tx_cbor(self, cbor) -> None:
            cbor_bytes = bytes.fromhex(cbor) if isinstance(cbor, str) else cbor
            try:
                self._backend.submit_tx(cbor_bytes)
            except NetworkError as e:
                raise GenesisTransaction.Error(f"Transaction submission failed: {e}") from e

    # ── Genesis datum / address helpers ───────────────────────────────────

    @classmethod
    def _build_owner_plutus_address(cls, account: "Wallet.DerivedAccount") -> PlutusAddress:
        return PlutusAddress(
            payment_credential=VerificationKeyCredential(
                bytes(account.payment_verification_key.hash())
            ),
            stake_credential=SomeStakeCredential(
                InlineStakeCredential(
                    VerificationKeyCredential(bytes(account.stake_verification_key.hash()))
                )
            ),
        )

    @classmethod
    def _build_master_datum(
        cls,
        perm_keys: "PermKeys.KeySet",
        owner_address: PlutusAddress,
        policy_id: bytes,
        asset_name_prefix: bytes,
    ) -> MasterDatum:
        """
        beacon_policy_id / beacon_asset_name are deliberately NOT passed
        here anymore - MasterDatum no longer carries those fields (see
        cardano_types.py). Canonical identity is now established purely
        by the script's own compile-time parameters, not by anything
        stored in the datum.
        """
        for name, value in [
            ("authority_key", perm_keys.authority_key),
            ("operator_key",  perm_keys.operator_key),
            ("owner_key",     perm_keys.owner_key),
        ]:
            if len(value) != 32:
                raise GenesisTransaction.Error(
                    f"{name} must be 32 bytes, got {len(value)}. "
                    f"Check perm_keys.json."
                )
        return MasterDatum(
            authority_key=perm_keys.authority_key,
            operator_key=perm_keys.operator_key,
            owner_key=perm_keys.owner_key,
            owner_address=owner_address,
            nonce=0,
            is_paused=AikenFalse(),
            policy_id=policy_id,
            asset_name_prefix=asset_name_prefix,
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

    # ── Main entry point ──────────────────────────────────────────────────

    @classmethod
    def run(
        cls,
        backend: NetworkBackend,
        network: Network,
        funding_account: "Wallet.DerivedAccount",
        genesis_utxo: UtxoInfo,
        compiled_code_hex: str,
        policy_id_hex: str,
        beacon_asset_name: bytes,
        asset_name_prefix: bytes,
        perm_keys: "PermKeys.KeySet",
    ) -> "GenesisTransaction.Result":

        context = cls._ProviderContext(backend, network)

        policy_id_bytes = bytes.fromhex(policy_id_hex)

        registry_script_address = Address(
            payment_part=ScriptHash(policy_id_bytes),
            network=network,
        )
        script = PlutusV3Script(bytes.fromhex(compiled_code_hex))

        genesis_utxo_obj = UTxO(
            input=TransactionInput(
                transaction_id=TransactionId(bytes.fromhex(genesis_utxo.tx_hash)),
                index=genesis_utxo.output_index,
            ),
            output=TransactionOutput(
                address=Address.from_primitive(genesis_utxo.address),
                amount=Value(coin=genesis_utxo.lovelace),
            ),
        )

        owner_plutus_address = cls._build_owner_plutus_address(funding_account)
        genesis_master_datum = cls._build_master_datum(
            perm_keys=perm_keys,
            owner_address=owner_plutus_address,
            policy_id=policy_id_bytes,
            asset_name_prefix=asset_name_prefix,
        )

        beacon_multi_asset = MultiAsset({
            ScriptHash(policy_id_bytes): Asset({AssetName(beacon_asset_name): 1})
        })

        builder = TransactionBuilder(context, ttl=context.last_block_slot + cls.TTL_BUFFER_SLOTS)
        builder.add_input(genesis_utxo_obj)
        builder.add_minting_script(script, Redeemer(MintBeacon()))
        builder.mint = beacon_multi_asset
        builder.add_output(TransactionOutput(
            address=registry_script_address,
            amount=Value(coin=cls.MASTER_UTXO_LOVELACE, multi_asset=beacon_multi_asset),
            datum=genesis_master_datum,
        ))

        try:
            signed_tx = builder.build_and_sign(
                signing_keys=[funding_account.payment_signing_key],
                change_address=funding_account.address,
            )
        except Exception as e:
            raise GenesisTransaction.Error(f"Failed to build/sign genesis transaction: {e}") from e

        try:
            context.submit_tx(signed_tx)
        except Exception as e:
            raise GenesisTransaction.Error(f"Failed to submit genesis transaction: {e}") from e

        tx_id = str(signed_tx.id)
        return GenesisTransaction.Result(
            tx_id=tx_id,
            master_utxo_ref=f"{tx_id}#0",
            registry_script_address=str(registry_script_address),
            policy_id_hex=policy_id_hex,
            beacon_asset_name_hex=beacon_asset_name.hex(),
        )


# ═══════════════════════════════════════════════════════════════════════════
# DeploymentRecord - writes deployment.json
# ═══════════════════════════════════════════════════════════════════════════
#
# deployment.json structure (SIMPLIFIED - single script, single policy ID):
#
# {
#   "network": ...,
#   "timestamp_utc": ...,
#   "deployed_from_wallet_address": ...,
#   "transaction_hash": ...,              <- the genesis bootstrap tx itself
#   "genesis_transaction_hash": ...,      <- the UTXO consumed as the script's genesis_ref parameter
#
#   "contract": { policy_id, script_address, bootstrap_generated_plutus_path },
#
#   "beacon": { asset_name_hex, asset_name_utf8 },
#       <- policy_id deliberately NOT repeated here: it's IDENTICAL to
#          contract.policy_id (same compiled script, same hash), so
#          duplicating it would misleadingly imply it could ever differ.
#
#   "master_utxo": {
#       utxo_ref, transaction_hash, output_index, script_address,
#       "beacon_token": { policy_id, asset_name_hex, asset_name_utf8,
#                          token_id, asset_fingerprint }
#   },
#
#   "permission_keys": { authority_key, operator_key, owner_key }
# }
#
# asset_fingerprint (CIP-14) is verified against all 5 official test
# vectors before being trusted here. If fingerprint computation ever fails
# for an unexpected reason, it degrades to None rather than blocking the
# write of an already-confirmed, on-chain-successful deployment record -
# it's a cosmetic/display field, not load-bearing for anything downstream.
#
# Verified against the 5 official CIP-14 test vectors
# (https://cips.cardano.org/cip/CIP-14) at the time this was written:
#   7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373 + ""
#       -> asset1rjklcrnsdzqp65wjgrg55sy9723kw09mlgvlc3
#   7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc37e + ""
#       -> asset1nl0puwxmhas8fawxp8nx4e2q3wekg969n2auw3
#   1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209 + ""
#       -> asset1uyuxku60yqe57nusqzjx38aan3f2wq6s93f6ea
#   7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373 + 504154415445
#       -> asset13n25uv0yaf5kus35fm2k86cqy60z58d9xmde92
#   1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209 + 504154415445
#       -> asset1hv4p5tv2a837mzqrst04d0dcptdjmluqvdx9k3
# All 5 passed exactly.

def _asset_fingerprint(policy_id: bytes, asset_name: bytes) -> str:
    """
    CIP-14 user-facing asset fingerprint: bech32-encoded blake2b-160 digest
    of the concatenation of RAW (decoded) policy_id and asset_name bytes -
    per spec, hex string forms must not be used for the digest input.
    """
    digest = hashlib.blake2b(policy_id + asset_name, digest_size=20).digest()
    words = bech32.convertbits(digest, 8, 5)
    return bech32.bech32_encode("asset", words)


class DeploymentRecord:
    """
    Namespace for building and persisting the deployment record.
    Never accepts or persists private key material.
    """

    class Error(Exception):
        pass

    @dataclass(frozen=True)
    class Record:
        network: str
        timestamp_utc: str
        deployed_from_wallet_address: str
        transaction_hash: str
        genesis_transaction_hash: str
        contract: dict
        beacon: dict
        master_utxo: dict
        permission_keys: dict

        def to_dict(self) -> dict:
            return asdict(self)

    @classmethod
    def build(
        cls,
        network: Network,
        funding_account: "Wallet.DerivedAccount",
        genesis_utxo: UtxoInfo,
        tx_result: "GenesisTransaction.Result",
        beacon_asset_name: bytes,
        perm_keys: "PermKeys.KeySet",
        blueprint_output_path: str | Path,
    ) -> "DeploymentRecord.Record":
        try:
            asset_name_utf8 = beacon_asset_name.decode("utf-8")
        except UnicodeDecodeError:
            asset_name_utf8 = None

        policy_id_bytes = bytes.fromhex(tx_result.policy_id_hex)
        token_id = tx_result.policy_id_hex + beacon_asset_name.hex()

        try:
            fingerprint = _asset_fingerprint(policy_id_bytes, beacon_asset_name)
        except Exception:
            # Cosmetic field only - see module-level note above. Never let
            # a fingerprint computation issue block writing the rest of an
            # already-confirmed, on-chain-successful deployment record.
            fingerprint = None

        # tx_result.master_utxo_ref is "{tx_hash}#{index}"
        master_tx_hash, _, master_index_str = tx_result.master_utxo_ref.partition("#")

        contract = {
            "policy_id": tx_result.policy_id_hex,
            "script_address": tx_result.registry_script_address,
            "bootstrap_generated_plutus_path": str(blueprint_output_path),
        }

        beacon = {
            "asset_name_hex": tx_result.beacon_asset_name_hex,
            "asset_name_utf8": asset_name_utf8,
        }

        master_utxo = {
            "utxo_ref": tx_result.master_utxo_ref,
            "transaction_hash": master_tx_hash,
            "output_index": int(master_index_str),
            "script_address": tx_result.registry_script_address,
            "beacon_token": {
                "policy_id": tx_result.policy_id_hex,
                "asset_name_hex": tx_result.beacon_asset_name_hex,
                "asset_name_utf8": asset_name_utf8,
                "token_id": token_id,
                "asset_fingerprint": fingerprint,
            },
        }

        return DeploymentRecord.Record(
            network=network.name,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            deployed_from_wallet_address=str(funding_account.address),
            transaction_hash=master_tx_hash,
            genesis_transaction_hash=genesis_utxo.tx_hash,
            contract=contract,
            beacon=beacon,
            master_utxo=master_utxo,
            permission_keys=perm_keys.as_dict(),
        )

    @classmethod
    def write(
        cls,
        record: "DeploymentRecord.Record",
        output_path: str | Path,
        allow_overwrite: bool = True,
    ) -> Path:
        output_path = Path(output_path)
        if output_path.exists() and not allow_overwrite:
            raise DeploymentRecord.Error(
                f"{output_path} already exists. Refusing to overwrite an existing "
                f"deployment record. Pass allow_overwrite=True or delete the file first."
            )
        try:
            output_path.write_text(json.dumps(record.to_dict(), indent=2))
        except OSError as e:
            raise DeploymentRecord.Error(f"Could not write {output_path}: {e}") from e
        return output_path