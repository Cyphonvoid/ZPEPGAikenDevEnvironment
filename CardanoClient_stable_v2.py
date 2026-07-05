"""
CardanoClient.py - Production Cardano client for the ZPEPG archive registry.

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

Supported operations:
  pause()         - Freeze all minting. Authority key required.
  resume()        - Unfreeze minting. Authority key required.
  mint()          - Mint a document token. Operator key required.
  withdraw()      - Withdraw lovelace to owner address. Owner key required.
  rotate_key()    - Rotate authority, operator, or owner key. Authority key required.
  link_forward()  - Seal a forward link to a successor deployment. Authority key required.
  link_backward() - Establish a backward link to a predecessor deployment. Authority key required.
  get_master_state() - Read current registry state. No keys required.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Optional, Protocol, runtime_checkable

from blockfrost import ApiError, ApiUrls
from pycardano import (
    Address, Asset, AssetName, BlockFrostChainContext, MultiAsset,
    Network, PaymentSigningKey, Redeemer, ScriptHash, TransactionBuilder,
    TransactionOutput, UTxO, Value,
)

try:
    from pycardano import min_lovelace_post_alonzo as _min_lovelace
except ImportError:
    from pycardano.utils import min_lovelace_post_alonzo as _min_lovelace

from CardanoDeployer.cardano_types import (
    AikenFalse, AikenTrue, DeploymentChainLink, MasterDatum,
    NoneChainLink, OutputReference, RegistryStats, SomeChainLink,
)
from test_types import (
    AuthorityKeyTag, LinkBackward, LinkForward, MintDocument, MintToken,
    OperatorKeyTag, OwnerKeyTag, Pause, Resume, TokenDatum, Withdraw,
    RotateKey,
)


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

    @property
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

    # ── Tunable constants ────────────────────────────────────────────────────
    TTL_BUFFER_SLOTS             = 500
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
            deployment_json_path:     Path to testnet_deployment_ref.json.
                                      Must have deployment_type == "reference".
            perm_keys_json_path:      Path to perm_keys.json.
            funding_signing_key_cbor: Raw cborHex of the funding payment key.
            backend:                  Network backend. Defaults to BlockfrostBackend
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

        self._policy_id      = bytes.fromhex(deployment["contract"]["policy_id"])
        self._script_address = Address.from_primitive(deployment["contract"]["script_address"])
        self._beacon_name    = bytes.fromhex(deployment["beacon"]["asset_name_hex"])
        self._script_hash    = ScriptHash(self._policy_id)

        ref = deployment["reference_script"]
        self._ref_script_tx_hash  = ref["tx_hash"]
        self._ref_script_tx_index = ref["output_index"]

        # ── Load permission keys ─────────────────────────────────────────
        perm_keys = json.loads(Path(perm_keys_json_path).read_text())
        self._operator_key  = bytes.fromhex(perm_keys["operator"]["private_key_hex"])
        self._authority_key = bytes.fromhex(perm_keys["authority"]["private_key_hex"])
        self._owner_key     = bytes.fromhex(perm_keys["owner"]["private_key_hex"])

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
                f"No ADA-only funding UTXO meets the collateral minimum "
                f"({self.COLLATERAL_MIN_LOVELACE} lovelace). "
                "Fund the wallet or consolidate UTxOs."
            )
        builder.collaterals.append(min(candidates, key=lambda u: u.output.amount.coin))

    def _new_builder(self) -> TransactionBuilder:
        return TransactionBuilder(
            self._backend,
            ttl=self._backend.last_block_slot + self.TTL_BUFFER_SLOTS,
        )

    def _base_spend_builder(
        self,
        master_utxo: UTxO,
        ref_utxo: UTxO,
        redeemer: Any,
    ) -> TransactionBuilder:
        """
        Build a base TransactionBuilder for any spend of the master UTXO.
        Callers add their specific outputs on top.
        """
        builder = self._new_builder()
        builder.add_input_address(self._funding_address)
        builder.add_script_input(
            utxo=master_utxo,
            redeemer=Redeemer(redeemer),
        )
        builder.reference_inputs.add(ref_utxo.input)
        self._attach_collateral(builder)
        return builder

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

            builder = self._base_spend_builder(master_utxo, ref_utxo, redeemer)
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

            builder = self._base_spend_builder(master_utxo, ref_utxo, redeemer)
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
        Mint a document token. Operator key required.

        Args:
            cross_chain_global_id: Human-readable global document identifier.
            sha256_hash:           Hex string of the document's SHA-256 hash (64 chars).
            upload_date:           ISO 8601 date string, e.g. "2026-07-04T00:00:00Z".
            version:               Document version integer.
            token_data:            Arbitrary metadata dict, JSON-serialized internally.
            is_unique_document:    Whether this counts as a unique document. Default True.
        """
        try:
            master_utxo, old_datum = self._get_master_utxo()
            ref_utxo = self._get_ref_utxo()

            if isinstance(old_datum.is_paused, AikenTrue):
                return OperationResult(
                    success=False, tx_hash=None,
                    error="Registry is paused. Resume before minting."
                )

            # ── Encode ────────────────────────────────────────────────────
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

            master_output = self._build_master_output(new_datum)
            token_output = TransactionOutput(
                address=self._script_address,
                amount=Value(coin=self.TOKEN_UTXO_FLOOR_LOVELACE, multi_asset=token_multi_asset),
                datum=token_datum,
            )

            builder = self._base_spend_builder(master_utxo, ref_utxo, redeemer)
            builder.add_output(master_output)
            builder.add_output(token_output)
            builder.add_minting_script(script=ref_utxo, redeemer=Redeemer(MintToken()))
            builder.mint = token_multi_asset
            return self._submit_and_confirm(builder)

        except Exception as e:
            return OperationResult(success=False, tx_hash=None, error=str(e))

    # ══════════════════════════════════════════════════════════════════════
    # Public: withdraw
    # ══════════════════════════════════════════════════════════════════════

    def withdraw(self, amount_lovelace: int) -> OperationResult:
        """
        Withdraw lovelace from the registry to the owner address. Owner key required.

        The owner address is stored in the master datum and cannot be changed
        without a RotateKey operation. The exact amount is sent to that address.

        Args:
            amount_lovelace: Amount in lovelace to withdraw.
        """
        try:
            master_utxo, old_datum = self._get_master_utxo()
            ref_utxo = self._get_ref_utxo()

            if amount_lovelace <= 0:
                return OperationResult(
                    success=False, tx_hash=None,
                    error=f"amount_lovelace must be positive, got {amount_lovelace}."
                )

            nonce = old_datum.nonce
            signed_payload = (
                self._int_to_be(nonce, 8)
                + b"WITHDRAW"
                + self._int_to_be(amount_lovelace, 8)
            )
            signature = self._sign_ed25519(self._owner_key, signed_payload)

            redeemer = Withdraw(nonce=nonce, amount=amount_lovelace, signature=signature)
            new_datum = self._carry_forward(old_datum)
            master_output = self._build_master_output(new_datum)

            # Build owner address from the PlutusAddress stored in datum.
            # The contract validates the output goes to old_datum.owner_address.
            owner_output = TransactionOutput(
                address=self._script_address,  # placeholder; overridden below
                amount=amount_lovelace,
            )
            # Reconstruct the pycardano Address from the datum's PlutusAddress.
            owner_plutus_addr = old_datum.owner_address
            from CardanoDeployer.cardano_types import VerificationKeyCredential, ScriptCredential
            from pycardano import VerificationKeyHash
            pay_cred = owner_plutus_addr.payment_credential
            if isinstance(pay_cred, VerificationKeyCredential):
                payment_part = VerificationKeyHash(pay_cred.credential_hash)
                owner_addr = Address(payment_part=payment_part, network=Network.TESTNET)
            else:
                owner_addr = Address(
                    payment_part=ScriptHash(pay_cred.credential_hash),
                    network=Network.TESTNET,
                )
            owner_output = TransactionOutput(address=owner_addr, amount=amount_lovelace)

            builder = self._base_spend_builder(master_utxo, ref_utxo, redeemer)
            builder.add_output(master_output)
            builder.add_output(owner_output)
            return self._submit_and_confirm(builder)

        except Exception as e:
            return OperationResult(success=False, tx_hash=None, error=str(e))

    # ══════════════════════════════════════════════════════════════════════
    # Public: rotate_key
    # ══════════════════════════════════════════════════════════════════════

    def rotate_key(
        self,
        key_type: Literal["authority", "operator", "owner"],
        new_public_key_hex: str,
    ) -> OperationResult:
        """
        Rotate one of the three permission keys. Authority key required.

        Args:
            key_type:           Which key to rotate: "authority", "operator", or "owner".
            new_public_key_hex: Hex string of the new 32-byte Ed25519 public key.
        """
        try:
            master_utxo, old_datum = self._get_master_utxo()
            ref_utxo = self._get_ref_utxo()

            new_key = bytes.fromhex(new_public_key_hex)
            if len(new_key) != 32:
                return OperationResult(
                    success=False, tx_hash=None,
                    error=f"new_public_key_hex must be 32 bytes (64 hex chars), got {len(new_key)}."
                )

            key_type_lower = key_type.lower()
            if key_type_lower == "authority":
                key_tag      = AuthorityKeyTag()
                key_type_str = b"AUTHORITY"
            elif key_type_lower == "operator":
                key_tag      = OperatorKeyTag()
                key_type_str = b"OPERATOR"
            elif key_type_lower == "owner":
                key_tag      = OwnerKeyTag()
                key_type_str = b"OWNER"
            else:
                return OperationResult(
                    success=False, tx_hash=None,
                    error=f"key_type must be 'authority', 'operator', or 'owner', got {key_type!r}."
                )

            nonce = old_datum.nonce
            signed_payload = (
                self._int_to_be(nonce, 8)
                + b"ROTATE"
                + key_type_str
                + new_key
            )
            signature = self._sign_ed25519(self._authority_key, signed_payload)

            redeemer = RotateKey(
                nonce=nonce,
                key_type=key_tag,
                new_key=new_key,
                signature=signature,
            )

            # Build the new datum with the rotated key.
            if key_type_lower == "authority":
                new_datum = self._carry_forward(old_datum, authority_key=new_key)
            elif key_type_lower == "operator":
                new_datum = self._carry_forward(old_datum, operator_key=new_key)
            else:
                new_datum = self._carry_forward(old_datum, owner_key=new_key)

            master_output = self._build_master_output(new_datum)

            builder = self._base_spend_builder(master_utxo, ref_utxo, redeemer)
            builder.add_output(master_output)
            return self._submit_and_confirm(builder)

        except Exception as e:
            return OperationResult(success=False, tx_hash=None, error=str(e))

    # ══════════════════════════════════════════════════════════════════════
    # Public: link_forward
    # ══════════════════════════════════════════════════════════════════════

    def link_forward(
        self,
        next_script_address: str,
        next_policy_id: str,
        link_reason: str,
        linked_at: int,
        instructions: str,
    ) -> OperationResult:
        """
        Seal a permanent forward link to a successor deployment. Authority key required.
        Can only be called once — the forward link slot is permanently locked after.

        Args:
            next_script_address: Bech32 address string of the successor script.
            next_policy_id:      Hex string of the successor contract's policy ID.
            link_reason:         Human-readable reason for the migration.
            linked_at:           Timestamp or epoch integer recorded in the link.
            instructions:        Human-readable migration instructions.
        """
        try:
            master_utxo, old_datum = self._get_master_utxo()
            ref_utxo = self._get_ref_utxo()

            next_script_address_bytes = next_script_address.encode("utf-8")
            next_policy_id_bytes      = bytes.fromhex(next_policy_id)
            link_reason_bytes         = link_reason.encode("utf-8")
            instructions_bytes        = instructions.encode("utf-8")

            nonce = old_datum.nonce
            signed_payload = (
                self._int_to_be(nonce, 8)
                + next_policy_id_bytes
                + next_script_address_bytes
                + link_reason_bytes
            )
            signature = self._sign_ed25519(self._authority_key, signed_payload)

            redeemer = LinkForward(
                nonce=nonce,
                next_script_address=next_script_address_bytes,
                next_policy_id=next_policy_id_bytes,
                link_reason=link_reason_bytes,
                linked_at=linked_at,
                instructions=instructions_bytes,
                signature=signature,
            )

            chain_link = DeploymentChainLink(
                next_script_address=next_script_address_bytes,
                next_policy_id=next_policy_id_bytes,
                link_reason=link_reason_bytes,
                linked_at=linked_at,
                instructions=instructions_bytes,
                current_authority_key=old_datum.authority_key,
                signature=signature,
                nonce_at_link=nonce,
            )
            new_datum = self._carry_forward(
                old_datum,
                forward_link=SomeChainLink(value=chain_link),
            )
            master_output = self._build_master_output(new_datum)

            builder = self._base_spend_builder(master_utxo, ref_utxo, redeemer)
            builder.add_output(master_output)
            return self._submit_and_confirm(builder)

        except Exception as e:
            return OperationResult(success=False, tx_hash=None, error=str(e))

    # ══════════════════════════════════════════════════════════════════════
    # Public: link_backward
    # ══════════════════════════════════════════════════════════════════════

    def link_backward(
        self,
        prev_script_address: str,
        prev_policy_id: str,
        link_reason: str,
        linked_at: int,
        instructions: str,
    ) -> OperationResult:
        """
        Establish a permanent backward link to a predecessor deployment. Authority key required.
        Can only be called once — the backward link slot is permanently locked after.

        Args:
            prev_script_address: Bech32 address string of the predecessor script.
            prev_policy_id:      Hex string of the predecessor contract's policy ID.
            link_reason:         Human-readable reason for the linkage.
            linked_at:           Timestamp or epoch integer recorded in the link.
            instructions:        Human-readable notes about the predecessor.
        """
        try:
            master_utxo, old_datum = self._get_master_utxo()
            ref_utxo = self._get_ref_utxo()

            prev_script_address_bytes = prev_script_address.encode("utf-8")
            prev_policy_id_bytes      = bytes.fromhex(prev_policy_id)
            link_reason_bytes         = link_reason.encode("utf-8")
            instructions_bytes        = instructions.encode("utf-8")

            nonce = old_datum.nonce
            signed_payload = (
                self._int_to_be(nonce, 8)
                + prev_policy_id_bytes
                + prev_script_address_bytes
                + link_reason_bytes
            )
            signature = self._sign_ed25519(self._authority_key, signed_payload)

            redeemer = LinkBackward(
                nonce=nonce,
                prev_script_address=prev_script_address_bytes,
                prev_policy_id=prev_policy_id_bytes,
                link_reason=link_reason_bytes,
                linked_at=linked_at,
                instructions=instructions_bytes,
                signature=signature,
            )

            chain_link = DeploymentChainLink(
                next_script_address=prev_script_address_bytes,
                next_policy_id=prev_policy_id_bytes,
                link_reason=link_reason_bytes,
                linked_at=linked_at,
                instructions=instructions_bytes,
                current_authority_key=old_datum.authority_key,
                signature=signature,
                nonce_at_link=nonce,
            )
            new_datum = self._carry_forward(
                old_datum,
                backward_link=SomeChainLink(value=chain_link),
            )
            master_output = self._build_master_output(new_datum)

            builder = self._base_spend_builder(master_utxo, ref_utxo, redeemer)
            builder.add_output(master_output)
            return self._submit_and_confirm(builder)

        except Exception as e:
            return OperationResult(success=False, tx_hash=None, error=str(e))

    # ══════════════════════════════════════════════════════════════════════
    # Public: read state
    # ══════════════════════════════════════════════════════════════════════

    def get_master_state(self) -> dict:
        """
        Read the current master registry state. Returns a plain dict.
        No keys required. Safe to call at any time.
        """
        utxo, datum = self._get_master_utxo()

        from CardanoDeployer.cardano_types import SomeChainLink as _SomeChainLink

        def _link_to_dict(link) -> Optional[dict]:
            if isinstance(link, _SomeChainLink):
                l = link.value
                return {
                    "next_script_address": l.next_script_address.decode("utf-8", errors="replace"),
                    "next_policy_id":      l.next_policy_id.hex(),
                    "link_reason":         l.link_reason.decode("utf-8", errors="replace"),
                    "linked_at":           l.linked_at,
                    "instructions":        l.instructions.decode("utf-8", errors="replace"),
                    "nonce_at_link":       l.nonce_at_link,
                }
            return None

        return {
            "utxo":                      f"{utxo.input.transaction_id}#{utxo.input.index}",
            "nonce":                     datum.nonce,
            "is_paused":                 isinstance(datum.is_paused, AikenTrue),
            "total_token_count":         datum.stats.total_token_count,
            "total_unique_documents":    datum.stats.total_unique_documents,
            "last_minted_at":            datum.stats.last_minted_at,
            "last_cross_chain_global_id": datum.stats.last_cross_chain_global_id.decode("utf-8", errors="replace"),
            "last_cardano_asset_id":     datum.stats.last_cardano_asset_id.hex(),
            "policy_id":                 self._policy_id.hex(),
            "asset_name_prefix":         datum.asset_name_prefix.decode("utf-8", errors="replace"),
            "authority_key":             datum.authority_key.hex(),
            "operator_key":              datum.operator_key.hex(),
            "owner_key":                 datum.owner_key.hex(),
            "forward_link":              _link_to_dict(datum.forward_link),
            "backward_link":             _link_to_dict(datum.backward_link),
        }