"""
cardano_client.py - Production Cardano client for the ZPEPG archive registry.

Design principles:
  - Reference script only: the compiled contract lives on-chain as a reference
    script UTXO. No script bytes are embedded in any transaction.
  - Pluggable backend: CardanoBackend protocol defines the interface. Swap
    implementations without touching client code.
  - Human-readable API: all public method signatures accept plain Python types
    (str, int, dict). Encoding to bytes, hex, CBOR happens internally.
  - Single-fetch master state: one Blockfrost call per operation, no double-fetch.
  - Three-stage confirmation: transaction-level -> script address catchup ->
    funding address catchup. No artificial delays.
  - Fully self-contained per call: each method fetches state, builds, signs,
    submits, confirms, and returns. No shared mutable state between calls.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Protocol, runtime_checkable

from blockfrost import ApiError, ApiUrls
from pycardano import (
    Address, Asset, AssetName, BlockFrostChainContext, MultiAsset,
    Network, PaymentSigningKey, Redeemer, ScriptHash, TransactionBuilder,
    TransactionInput, TransactionOutput, UTxO, Value,
)
from pycardano import TransactionId as PyCardanoTransactionId

try:
    from pycardano import min_lovelace_post_alonzo as _min_lovelace
except ImportError:
    from pycardano.utils import min_lovelace_post_alonzo as _min_lovelace

from CardanoDeployer.cardano_types import (
    AikenFalse, AikenTrue, MasterDatum, OutputReference, RegistryStats,
)
from test_types import MintDocument, MintToken, Pause, Resume, TokenDatum


# ══════════════════════════════════════════════════════════════════════════════
# Result type
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class OperationResult:
    """Returned by every write method."""
    success: bool
    tx_hash: Optional[str]
    error: Optional[str]

    def __bool__(self):
        return self.success


# ══════════════════════════════════════════════════════════════════════════════
# Backend protocol
# ══════════════════════════════════════════════════════════════════════════════

@runtime_checkable
class CardanoBackend(Protocol):
    """
    Minimum interface any network backend must implement.
    CardanoClient calls only these methods - never touches provider internals.
    """

    def utxos(self, address: Address) -> list[UTxO]:
        """Return all UTxOs at the given address."""
        ...

    def submit_tx(self, tx) -> None:
        """Submit a signed transaction to the network."""
        ...

    def evaluate_tx_cbor(self, cbor: str) -> dict:
        """Evaluate script execution units. Returns {key: ExecutionUnits}."""
        ...

    def last_block_slot(self) -> int:
        """Return the slot number of the most recent block."""
        ...

    def transaction_utxos(self, tx_hash: str) -> Any:
        """
        Return transaction UTxO info if confirmed, raise ApiError(404) if not.
        Used by _confirm() stage 1.
        """
        ...


# ══════════════════════════════════════════════════════════════════════════════
# Blockfrost backend
# ══════════════════════════════════════════════════════════════════════════════

class BlockfrostBackend:
    """
    Preprod (testnet) backend backed by Blockfrost.
    Implements CardanoBackend by delegating to pycardano's BlockFrostChainContext
    and the raw Blockfrost API client for confirmation polling.
    """

    PREPROD_PROJECT_ID = "preprodviqzO4lW7gcYXeQoxtAg50qneXkq00dW"

    def __init__(self):
        self._context = BlockFrostChainContext(
            project_id=self.PREPROD_PROJECT_ID,
            network=Network.TESTNET,
            base_url=ApiUrls.preprod.value,
        )

    # ── CardanoBackend protocol ────────────────────────────────────────────

    def utxos(self, address: Address) -> list[UTxO]:
        return self._context.utxos(address)

    def submit_tx(self, tx) -> None:
        self._context.submit_tx(tx)

    def evaluate_tx_cbor(self, cbor: str) -> dict:
        return self._context.evaluate_tx_cbor(cbor)

    @property
    def last_block_slot(self) -> int:
        return self._context.last_block_slot

    def transaction_utxos(self, tx_hash: str) -> Any:
        return self._context.api.transaction_utxos(hash=tx_hash)

    # ── Protocol params (needed by pycardano's TransactionBuilder) ─────────

    @property
    def protocol_param(self):
        return self._context.protocol_param

    @property
    def network(self):
        return self._context.network

    @property
    def epoch(self):
        return self._context.epoch

    @property
    def genesis_param(self):
        return self._context.genesis_param

    # ── Delegate everything else to the underlying context ─────────────────

    def __getattr__(self, name):
        return getattr(self._context, name)


# ══════════════════════════════════════════════════════════════════════════════
# CardanoClient
# ══════════════════════════════════════════════════════════════════════════════

class CardanoClient:
    """
    Client for the ZPEPG archive_registry contract.

    Requires a reference-type deployment JSON (produced by
    deploy_reference_script.py). The contract script must already be
    deployed as a reference script UTXO on-chain — this client never
    embeds script bytes in any transaction.

    All public methods accept plain Python types. Encoding is internal.
    Every method is fully self-contained: fetch -> build -> sign -> submit
    -> confirm -> return. No shared mutable state between calls.
    """

    # ── Timing constants ────────────────────────────────────────────────────
    TTL_BUFFER_SLOTS             = 200
    MASTER_UTXO_FLOOR_LOVELACE   = 3_000_000
    TOKEN_UTXO_FLOOR_LOVELACE    = 3_000_000
    COLLATERAL_MIN_LOVELACE      = 5_000_000

    # Confirmation stage timeouts (seconds)
    CONFIRMATION_TIMEOUT_S       = 300.0
    CONFIRMATION_POLL_INTERVAL_S = 5.0
    ADDRESS_CATCHUP_TIMEOUT_S    = 30.0
    ADDRESS_CATCHUP_POLL_S       = 2.0
    FUNDING_CATCHUP_TIMEOUT_S    = 30.0
    FUNDING_CATCHUP_POLL_S       = 2.0

    def __init__(
        self,
        deployment_json_path: str,
        perm_keys_json_path: str,
        funding_signing_key_cbor: str,
        backend: Optional[CardanoBackend] = None,
    ):
        """
        Args:
            deployment_json_path:    Path to testnet_deployment_ref.json.
                                     Must have deployment_type == "reference".
            perm_keys_json_path:     Path to perm_keys.json.
            funding_signing_key_cbor: Raw cborHex of the funding payment key.
            backend:                 Network backend. Defaults to BlockfrostBackend
                                     (preprod). Pass a custom implementation to
                                     use a different provider or network.
        """
        # ── Load deployment ──────────────────────────────────────────────
        deployment = json.loads(Path(deployment_json_path).read_text())

        if deployment.get("deployment_type") != "reference":
            raise ValueError(
                f"{deployment_json_path} is not a reference deployment "
                f"(deployment_type={deployment.get('deployment_type')!r}). "
                f"Run deploy_reference_script.py first."
            )

        self._policy_id       = bytes.fromhex(deployment["contract"]["policy_id"])
        self._script_address  = Address.from_primitive(deployment["contract"]["script_address"])
        self._beacon_name     = bytes.fromhex(deployment["beacon"]["asset_name_hex"])
        self._script_hash     = ScriptHash(self._policy_id)

        ref = deployment["reference_script"]
        self._ref_script_tx_hash = ref["tx_hash"]
        self._ref_script_tx_index = ref["output_index"]

        # ── Load permission keys ─────────────────────────────────────────
        perm_keys = json.loads(Path(perm_keys_json_path).read_text())
        self._operator_key  = bytes.fromhex(perm_keys["operator"]["private_key_hex"])
        self._authority_key = bytes.fromhex(perm_keys["authority"]["private_key_hex"])

        # ── Load funding key ─────────────────────────────────────────────
        self._funding_key = PaymentSigningKey.from_cbor(funding_signing_key_cbor)
        self._funding_address = Address(
            payment_part=self._funding_key.to_verification_key().hash(),
            network=Network.TESTNET,
        )

        # ── Backend ──────────────────────────────────────────────────────
        self._backend = backend if backend is not None else BlockfrostBackend()

        # ── Reference script UTXO (fetched lazily, cached for lifetime) ──
        self._ref_utxo: Optional[UTxO] = None

    # ══════════════════════════════════════════════════════════════════════
    # Internal: reference script UTXO
    # ══════════════════════════════════════════════════════════════════════

    def _get_ref_utxo(self) -> UTxO:
        """
        Fetch and cache the reference script UTXO. Cached for the client's
        lifetime — the UTXO is permanent and can never be spent.
        """
        if self._ref_utxo is not None:
            return self._ref_utxo

        utxos = self._backend.utxos(self._script_address)
        for u in utxos:
            if (str(u.input.transaction_id) == self._ref_script_tx_hash
                    and u.input.index == self._ref_script_tx_index):
                self._ref_utxo = u
                return u

        raise RuntimeError(
            f"Reference script UTXO {self._ref_script_tx_hash}#{self._ref_script_tx_index} "
            f"not found at script address. Has it been deployed?"
        )

    # ══════════════════════════════════════════════════════════════════════
    # Internal: master UTXO
    # ══════════════════════════════════════════════════════════════════════

    def _get_master_utxo(self) -> tuple[UTxO, MasterDatum]:
        """
        Single Blockfrost call. Returns (utxo, datum) for the UTXO at the
        script address that holds the beacon token. Raises on failure.
        """
        utxos = self._backend.utxos(self._script_address)
        for u in utxos:
            qty = u.output.amount.multi_asset.get(
                ScriptHash(self._policy_id), {}
            ).get(AssetName(self._beacon_name))
            if qty == 1:
                if u.output.datum is None:
                    raise RuntimeError("Master UTXO has no inline datum.")
                datum = MasterDatum.from_cbor(u.output.datum.cbor)
                return u, datum
        raise RuntimeError(
            "No UTXO at the script address holds the beacon token. "
            "Is the deployment correct?"
        )

    # ══════════════════════════════════════════════════════════════════════
    # Internal: transaction building helpers
    # ══════════════════════════════════════════════════════════════════════

    def _build_master_output(self, new_datum: MasterDatum) -> TransactionOutput:
        """Build the successor master UTXO output with correct min-lovelace."""
        beacon_multi_asset = MultiAsset({
            ScriptHash(self._policy_id): Asset({AssetName(self._beacon_name): 1})
        })
        output = TransactionOutput(
            address=self._script_address,
            amount=Value(coin=self.MASTER_UTXO_FLOOR_LOVELACE, multi_asset=beacon_multi_asset),
            datum=new_datum,
        )
        required = max(self.MASTER_UTXO_FLOOR_LOVELACE, _min_lovelace(output, self._backend))
        output.amount = Value(coin=required, multi_asset=beacon_multi_asset)
        return output

    def _attach_collateral(self, builder: TransactionBuilder) -> None:
        """Pick the smallest ADA-only funding UTXO that clears the collateral floor."""
        candidates = [
            u for u in self._backend.utxos(self._funding_address)
            if not u.output.amount.multi_asset
            and u.output.amount.coin >= self.COLLATERAL_MIN_LOVELACE
        ]
        if not candidates:
            raise RuntimeError(
                "No ADA-only funding UTXO meets the collateral minimum "
                f"({self.COLLATERAL_MIN_LOVELACE} lovelace). "
                "Fund the wallet or consolidate UTxOs."
            )
        builder.collaterals.append(min(candidates, key=lambda u: u.output.amount.coin))

    def _new_builder(self) -> TransactionBuilder:
        return TransactionBuilder(
            self._backend,
            ttl=self._backend.last_block_slot + self.TTL_BUFFER_SLOTS,
        )

    @staticmethod
    def _carry_forward(old: MasterDatum, **overrides) -> MasterDatum:
        fields = dict(
            authority_key=old.authority_key,
            operator_key=old.operator_key,
            owner_key=old.owner_key,
            owner_address=old.owner_address,
            nonce=old.nonce + 1,
            is_paused=old.is_paused,
            policy_id=old.policy_id,
            asset_name_prefix=old.asset_name_prefix,
            forward_link=old.forward_link,
            backward_link=old.backward_link,
            stats=old.stats,
        )
        fields.update(overrides)
        return MasterDatum(**fields)

    # ══════════════════════════════════════════════════════════════════════
    # Internal: Ed25519 signing
    # ══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _sign_ed25519(private_key_32: bytes, message: bytes) -> bytes:
        from nacl.signing import SigningKey
        return SigningKey(private_key_32).sign(message).signature

    @staticmethod
    def _int_to_be(value: int, length: int) -> bytes:
        return value.to_bytes(length, byteorder="big", signed=False)

    # ══════════════════════════════════════════════════════════════════════
    # Internal: three-stage confirmation
    # ══════════════════════════════════════════════════════════════════════

    def _confirm(self, tx_hash: str) -> tuple[bool, Optional[str]]:
        """
        Three-stage confirmation:
          1. Poll transaction_utxos() until the tx is confirmed.
          2. Poll script address until master UTXO reflects the new tx.
          3. Poll funding address until change output appears.
        Returns (True, None) on success or (False, error_message) on timeout.
        """
        deadline = time.monotonic() + self.CONFIRMATION_TIMEOUT_S
        last_err = None

        # ── Stage 1: transaction-level confirmation ──────────────────────
        while time.monotonic() < deadline:
            try:
                result = self._backend.transaction_utxos(tx_hash)
                if getattr(result, "outputs", None):
                    break
            except ApiError as e:
                last_err = str(e)
            time.sleep(self.CONFIRMATION_POLL_INTERVAL_S)
        else:
            return False, (
                f"Transaction-level confirmation timeout after "
                f"{self.CONFIRMATION_TIMEOUT_S}s. Last error: {last_err}"
            )

        # ── Stage 2: script address (master UTXO) catchup ────────────────
        addr_deadline = time.monotonic() + self.ADDRESS_CATCHUP_TIMEOUT_S
        while time.monotonic() < addr_deadline:
            try:
                master_utxo, _ = self._get_master_utxo()
                if str(master_utxo.input.transaction_id) == tx_hash:
                    break
            except Exception as e:
                last_err = str(e)
            time.sleep(self.ADDRESS_CATCHUP_POLL_S)
        else:
            return False, (
                f"Script address did not reflect tx {tx_hash} within "
                f"{self.ADDRESS_CATCHUP_TIMEOUT_S}s. Last error: {last_err}"
            )

        # ── Stage 3: funding address (change output) catchup ─────────────
        fund_deadline = time.monotonic() + self.FUNDING_CATCHUP_TIMEOUT_S
        while time.monotonic() < fund_deadline:
            try:
                utxos = self._backend.utxos(self._funding_address)
                if any(str(u.input.transaction_id) == tx_hash for u in utxos):
                    return True, None
            except Exception as e:
                last_err = str(e)
            time.sleep(self.FUNDING_CATCHUP_POLL_S)

        return False, (
            f"Funding address did not reflect change output for tx {tx_hash} "
            f"within {self.FUNDING_CATCHUP_TIMEOUT_S}s. Last error: {last_err}"
        )

    # ══════════════════════════════════════════════════════════════════════
    # Internal: submit and confirm
    # ══════════════════════════════════════════════════════════════════════

    def _submit_and_confirm(self, builder: TransactionBuilder) -> OperationResult:
        try:
            signed_tx = builder.build_and_sign(
                signing_keys=[self._funding_key],
                change_address=self._funding_address,
            )
            tx_hash = str(signed_tx.id)
            self._backend.submit_tx(signed_tx)
            confirmed, err = self._confirm(tx_hash)
            return OperationResult(success=confirmed, tx_hash=tx_hash, error=err)
        except Exception as e:
            return OperationResult(success=False, tx_hash=None, error=str(e))

    # ══════════════════════════════════════════════════════════════════════
    # Public: pause
    # ══════════════════════════════════════════════════════════════════════

    def pause(self) -> OperationResult:
        """
        Pause the registry. Only the authority key can do this.
        Fails if already paused.
        """
        try:
            master_utxo, old_datum = self._get_master_utxo()
            ref_utxo = self._get_ref_utxo()

            if isinstance(old_datum.is_paused, AikenTrue):
                return OperationResult(
                    success=False, tx_hash=None, error="Registry is already paused."
                )

            nonce = old_datum.nonce
            signature = self._sign_ed25519(
                self._authority_key,
                self._int_to_be(nonce, 8) + b"PAUSE",
            )
            redeemer = Pause(nonce=nonce, signature=signature)
            new_datum = self._carry_forward(old_datum, is_paused=AikenTrue())
            master_output = self._build_master_output(new_datum)

            builder = self._new_builder()
            builder.add_input_address(self._funding_address)
            builder.add_script_input(
                utxo=master_utxo,
                redeemer=Redeemer(redeemer),
            )
            builder.reference_inputs.add(ref_utxo.input)
            self._attach_collateral(builder)
            builder.add_output(master_output)

            return self._submit_and_confirm(builder)

        except Exception as e:
            return OperationResult(success=False, tx_hash=None, error=str(e))

    # ══════════════════════════════════════════════════════════════════════
    # Public: resume
    # ══════════════════════════════════════════════════════════════════════

    def resume(self) -> OperationResult:
        """
        Resume the registry. Only the authority key can do this.
        Fails if not paused.
        """
        try:
            master_utxo, old_datum = self._get_master_utxo()
            ref_utxo = self._get_ref_utxo()

            if isinstance(old_datum.is_paused, AikenFalse):
                return OperationResult(
                    success=False, tx_hash=None, error="Registry is not paused."
                )

            nonce = old_datum.nonce
            signature = self._sign_ed25519(
                self._authority_key,
                self._int_to_be(nonce, 8) + b"RESUME",
            )
            redeemer = Resume(nonce=nonce, signature=signature)
            new_datum = self._carry_forward(old_datum, is_paused=AikenFalse())
            master_output = self._build_master_output(new_datum)

            builder = self._new_builder()
            builder.add_input_address(self._funding_address)
            builder.add_script_input(
                utxo=master_utxo,
                redeemer=Redeemer(redeemer),
            )
            builder.reference_inputs.add(ref_utxo.input)
            self._attach_collateral(builder)
            builder.add_output(master_output)

            return self._submit_and_confirm(builder)

        except Exception as e:
            return OperationResult(success=False, tx_hash=None, error=str(e))

    # ══════════════════════════════════════════════════════════════════════
    # Public: mint
    # ══════════════════════════════════════════════════════════════════════

    def mint(
        self,
        cross_chain_global_id: str,
        sha256_hash: str,
        upload_date: str,
        version: int,
        token_data: dict,
        is_unique_document: bool = True,
    ) -> OperationResult:
        """
        Mint a document token.

        Args:
            cross_chain_global_id: Human-readable global document identifier.
            sha256_hash:           Hex string of the document's SHA-256 hash.
            upload_date:           ISO 8601 date string, e.g. "2026-07-04T00:00:00Z".
            version:               Document version integer.
            token_data:            Arbitrary metadata dict, JSON-serialized internally.
            is_unique_document:    Whether this counts as a unique document. Default True.

        Returns:
            OperationResult(success, tx_hash, error)
        """
        try:
            master_utxo, old_datum = self._get_master_utxo()
            ref_utxo = self._get_ref_utxo()

            if isinstance(old_datum.is_paused, AikenTrue):
                return OperationResult(
                    success=False, tx_hash=None, error="Registry is paused. Resume before minting."
                )

            # ── Encode arguments ──────────────────────────────────────────
            cross_chain_global_id_bytes = cross_chain_global_id.encode("utf-8")
            sha256_hash_bytes           = bytes.fromhex(sha256_hash)
            upload_date_bytes           = upload_date.encode("utf-8")
            token_data_bytes            = json.dumps(token_data, separators=(",", ":")).encode("utf-8")

            if len(sha256_hash_bytes) != 32:
                return OperationResult(
                    success=False, tx_hash=None,
                    error=f"sha256_hash must be 32 bytes (64 hex chars), got {len(sha256_hash_bytes)}."
                )

            # ── Sign ──────────────────────────────────────────────────────
            nonce = old_datum.nonce
            signed_payload = (
                self._int_to_be(nonce, 8)
                + cross_chain_global_id_bytes
                + sha256_hash_bytes
                + self._int_to_be(version, 4)
            )
            signature = self._sign_ed25519(self._operator_key, signed_payload)

            # ── Redeemer ──────────────────────────────────────────────────
            redeemer = MintDocument(
                nonce=nonce,
                cross_chain_global_id=cross_chain_global_id_bytes,
                sha256_hash=sha256_hash_bytes,
                upload_date=upload_date_bytes,
                version=version,
                token_data=token_data_bytes,
                is_unique_document=AikenTrue() if is_unique_document else AikenFalse(),
                valid_lower_bound=nonce,
                signature=signature,
            )

            # ── Asset name and token ID ───────────────────────────────────
            asset_name = old_datum.asset_name_prefix + self._int_to_be(nonce, 4)
            token_id   = self._policy_id + asset_name
            token_multi_asset = MultiAsset({
                ScriptHash(self._policy_id): Asset({AssetName(asset_name): 1})
            })

            # ── New master datum ──────────────────────────────────────────
            unique_inc = 1 if is_unique_document else 0
            new_datum = self._carry_forward(
                old_datum,
                stats=RegistryStats(
                    total_token_count=old_datum.stats.total_token_count + 1,
                    total_unique_documents=old_datum.stats.total_unique_documents + unique_inc,
                    last_minted_at=nonce,
                    last_cross_chain_global_id=cross_chain_global_id_bytes,
                    last_cardano_asset_id=token_id,
                ),
            )

            # ── Token datum ───────────────────────────────────────────────
            token_datum = TokenDatum(
                cardano_asset_id=token_id,
                cross_chain_global_id=cross_chain_global_id_bytes,
                registry_address=b"",
                policy_id=self._policy_id,
                source_registry_master_utxo_reference=OutputReference(
                    transaction_id=master_utxo.input.transaction_id.payload,
                    output_index=master_utxo.input.index,
                ),
                sha256_hash=sha256_hash_bytes,
                upload_date=upload_date_bytes,
                version=version,
                token_data=token_data_bytes,
            )

            # ── Outputs ───────────────────────────────────────────────────
            master_output = self._build_master_output(new_datum)
            token_output = TransactionOutput(
                address=self._script_address,
                amount=Value(coin=self.TOKEN_UTXO_FLOOR_LOVELACE, multi_asset=token_multi_asset),
                datum=token_datum,
            )

            # ── Build ─────────────────────────────────────────────────────
            builder = self._new_builder()
            builder.add_input_address(self._funding_address)
            builder.add_script_input(
                utxo=master_utxo,
                redeemer=Redeemer(redeemer),
            )
            
            self._attach_collateral(builder)
            builder.add_output(master_output)
            builder.add_output(token_output)
            builder.add_minting_script(
                script=ref_utxo,
                redeemer=Redeemer(MintToken()),
            )
            builder.mint = token_multi_asset

            return self._submit_and_confirm(builder)

        except Exception as e:
            return OperationResult(success=False, tx_hash=None, error=str(e))

    # ══════════════════════════════════════════════════════════════════════
    # Public: read state
    # ══════════════════════════════════════════════════════════════════════

    def get_master_state(self) -> dict:
        """
        Read the current master registry state. Returns a plain dict.
        Useful for inspection, testing, and the stress test script.
        """
        utxo, datum = self._get_master_utxo()
        return {
            "utxo": f"{utxo.input.transaction_id}#{utxo.input.index}",
            "nonce": datum.nonce,
            "is_paused": isinstance(datum.is_paused, AikenTrue),
            "total_token_count": datum.stats.total_token_count,
            "total_unique_documents": datum.stats.total_unique_documents,
            "last_minted_at": datum.stats.last_minted_at,
            "last_cross_chain_global_id": datum.stats.last_cross_chain_global_id.decode("utf-8", errors="replace"),
            "policy_id": self._policy_id.hex(),
        }