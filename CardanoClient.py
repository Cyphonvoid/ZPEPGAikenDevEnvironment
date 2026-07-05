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
  - Rich receipts: every method returns a flat dict mirroring the TON client's
    receipt pattern, with operation-specific fields, error_type classification,
    timing info, and a nested receipt_json string for storage.

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
from pathlib import Path
from typing import Any, Literal, Optional, Protocol, runtime_checkable

from blockfrost import ApiError, ApiUrls
from pycardano import (
    Address, Asset, AssetName, BlockFrostChainContext, MultiAsset,
    Network, PaymentSigningKey, Redeemer, ScriptHash, TransactionBuilder,
    TransactionOutput, UTxO, Value, VerificationKeyHash,
)

try:
    from pycardano import min_lovelace_post_alonzo as _min_lovelace
except ImportError:
    from pycardano.utils import min_lovelace_post_alonzo as _min_lovelace

from CardanoDeployer.cardano_types import (
    AikenFalse, AikenTrue, DeploymentChainLink, MasterDatum,
    NoneChainLink, OutputReference, RegistryStats, SomeChainLink,
    VerificationKeyCredential,
)
from test_types import (
    AuthorityKeyTag, LinkBackward, LinkForward, MintDocument, MintToken,
    OperatorKeyTag, OwnerKeyTag, Pause, Resume, TokenDatum, Withdraw,
    RotateKey,
)


# ══════════════════════════════════════════════════════════════════════════════
# Error type constants
# ══════════════════════════════════════════════════════════════════════════════

ERROR_INVALID_INPUT       = "invalid_input"
ERROR_SCRIPT_REJECTED     = "script_rejected"
ERROR_CONFIRMATION_TIMEOUT = "confirmation_timeout"
ERROR_NETWORK_ERROR       = "network_error"


# ══════════════════════════════════════════════════════════════════════════════
# Receipt helpers
# ══════════════════════════════════════════════════════════════════════════════

def _failure(
    operation: str,
    error: str,
    error_type: str,
    nonce_used: Optional[int] = None,
    tx_hash: Optional[str] = None,
    submitted_at: Optional[float] = None,
    duration_s: Optional[float] = None,
) -> dict:
    return {
        "success":      False,
        "operation":    operation,
        "tx_status":    "failed",
        "tx_hash":      tx_hash,
        "error":        error,
        "error_type":   error_type,
        "nonce_used":   nonce_used,
        "nonce_after":  None,
        "fee_lovelace": None,
        "submitted_at": submitted_at,
        "confirmed_at": None,
        "duration_s":   duration_s,
        "receipt_json": None,
    }


def _success(
    operation: str,
    tx_hash: str,
    fee_lovelace: int,
    nonce_used: int,
    nonce_after: int,
    submitted_at: float,
    confirmed_at: float,
    extra: Optional[dict] = None,
) -> dict:
    base = {
        "success":      True,
        "operation":    operation,
        "tx_status":    "confirmed",
        "tx_hash":      tx_hash,
        "error":        None,
        "error_type":   None,
        "nonce_used":   nonce_used,
        "nonce_after":  nonce_after,
        "fee_lovelace": fee_lovelace,
        "submitted_at": submitted_at,
        "confirmed_at": confirmed_at,
        "duration_s":   round(confirmed_at - submitted_at, 2),
    }
    if extra:
        base.update(extra)
    receipt = {k: v for k, v in base.items() if k != "receipt_json"}
    base["receipt_json"] = json.dumps(receipt)
    return base


def _classify_error(e: Exception) -> str:
    """Classify an exception into one of the four error_type constants."""
    msg = str(e).lower()
    if "400" in msg or "script" in msg or "validation" in msg or "plutus" in msg:
        return ERROR_SCRIPT_REJECTED
    if "timeout" in msg:
        return ERROR_CONFIRMATION_TIMEOUT
    return ERROR_NETWORK_ERROR


# ══════════════════════════════════════════════════════════════════════════════
# Backend protocol
# ══════════════════════════════════════════════════════════════════════════════

@runtime_checkable
class CardanoBackend(Protocol):
    """
    Minimum interface any network backend must implement.
    CardanoClient calls only these methods — never touches provider internals.
    """

    def utxos(self, address: Address) -> list[UTxO]: ...
    def submit_tx(self, tx) -> None: ...
    def evaluate_tx_cbor(self, cbor: str) -> dict: ...

    @property
    def last_block_slot(self) -> int: ...

    def transaction_utxos(self, tx_hash: str) -> Any: ...


# ══════════════════════════════════════════════════════════════════════════════
# Blockfrost backend
# ══════════════════════════════════════════════════════════════════════════════

class BlockfrostBackend:
    """
    Preprod (testnet) Blockfrost backend. Implements CardanoBackend.
    Project ID is hardcoded — swap for a different backend class to change provider.
    """

    PREPROD_PROJECT_ID = "preprodviqzO4lW7gcYXeQoxtAg50qneXkq00dW"

    def __init__(self):
        self._context = BlockFrostChainContext(
            project_id=self.PREPROD_PROJECT_ID,
            network=Network.TESTNET,
            base_url=ApiUrls.preprod.value,
        )

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
    deployed as a reference script UTXO on-chain.

    All public methods accept plain Python types and return a flat dict
    receipt following the ZPEPG client receipt pattern.
    """

    TTL_BUFFER_SLOTS             = 500
    MASTER_UTXO_FLOOR_LOVELACE   = 3_000_000
    TOKEN_UTXO_FLOOR_LOVELACE    = 3_000_000
    COLLATERAL_MIN_LOVELACE      = 5_000_000

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

        perm_keys = json.loads(Path(perm_keys_json_path).read_text())
        self._operator_key  = bytes.fromhex(perm_keys["operator"]["private_key_hex"])
        self._authority_key = bytes.fromhex(perm_keys["authority"]["private_key_hex"])
        self._owner_key     = bytes.fromhex(perm_keys["owner"]["private_key_hex"])

        self._funding_key = PaymentSigningKey.from_cbor(funding_signing_key_cbor)
        self._funding_address = Address(
            payment_part=self._funding_key.to_verification_key().hash(),
            network=Network.TESTNET,
        )

        self._backend = backend if backend is not None else BlockfrostBackend()
        self._ref_utxo: Optional[UTxO] = None

    # ══════════════════════════════════════════════════════════════════════
    # Internal: reference script UTXO
    # ══════════════════════════════════════════════════════════════════════

    def _get_ref_utxo(self) -> UTxO:
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
            f"not found at script address."
        )

    # ══════════════════════════════════════════════════════════════════════
    # Internal: master UTXO
    # ══════════════════════════════════════════════════════════════════════

    def _get_master_utxo(self) -> tuple[UTxO, MasterDatum]:
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
        raise RuntimeError("No UTXO at the script address holds the beacon token.")

    # ══════════════════════════════════════════════════════════════════════
    # Internal: transaction building helpers
    # ══════════════════════════════════════════════════════════════════════

    def _build_master_output(self, new_datum: MasterDatum) -> TransactionOutput:
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
        candidates = [
            u for u in self._backend.utxos(self._funding_address)
            if not u.output.amount.multi_asset
            and u.output.amount.coin >= self.COLLATERAL_MIN_LOVELACE
        ]
        if not candidates:
            raise RuntimeError(
                f"No ADA-only funding UTXO meets the collateral minimum "
                f"({self.COLLATERAL_MIN_LOVELACE} lovelace)."
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
        builder = self._new_builder()
        builder.add_input_address(self._funding_address)
        builder.add_script_input(utxo=master_utxo, redeemer=Redeemer(redeemer))
        builder.reference_inputs.add(ref_utxo.input)
        self._attach_collateral(builder)
        return builder

    @staticmethod
    def _carry_forward(old: MasterDatum, **overrides) -> MasterDatum:
        fields = dict(
            authority_key=old.authority_key, operator_key=old.operator_key,
            owner_key=old.owner_key, owner_address=old.owner_address,
            nonce=old.nonce + 1, is_paused=old.is_paused,
            policy_id=old.policy_id, asset_name_prefix=old.asset_name_prefix,
            forward_link=old.forward_link, backward_link=old.backward_link,
            stats=old.stats,
        )
        fields.update(overrides)
        return MasterDatum(**fields)

    # ══════════════════════════════════════════════════════════════════════
    # Internal: signing
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

    def _confirm(self, tx_hash: str) -> tuple[bool, Optional[str], Optional[str]]:
        """
        Returns (confirmed, error_message, error_type).
        """
        deadline = time.monotonic() + self.CONFIRMATION_TIMEOUT_S
        last_err = None

        # Stage 1: transaction-level
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
            ), ERROR_CONFIRMATION_TIMEOUT

        # Stage 2: script address catchup
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
            ), ERROR_CONFIRMATION_TIMEOUT

        # Stage 3: funding address catchup
        fund_deadline = time.monotonic() + self.FUNDING_CATCHUP_TIMEOUT_S
        while time.monotonic() < fund_deadline:
            try:
                utxos = self._backend.utxos(self._funding_address)
                if any(str(u.input.transaction_id) == tx_hash for u in utxos):
                    return True, None, None
            except Exception as e:
                last_err = str(e)
            time.sleep(self.FUNDING_CATCHUP_POLL_S)

        return False, (
            f"Funding address did not reflect change output for tx {tx_hash} "
            f"within {self.FUNDING_CATCHUP_TIMEOUT_S}s. Last error: {last_err}"
        ), ERROR_CONFIRMATION_TIMEOUT

    # ══════════════════════════════════════════════════════════════════════
    # Internal: build, sign, submit, confirm — returns receipt dict
    # ══════════════════════════════════════════════════════════════════════

    def _submit_and_confirm(
        self,
        builder: TransactionBuilder,
        operation: str,
        nonce_used: int,
        extra: Optional[dict] = None,
    ) -> dict:
        submitted_at = time.time()
        try:
            signed_tx = builder.build_and_sign(
                signing_keys=[self._funding_key],
                change_address=self._funding_address,
            )
            tx_hash      = str(signed_tx.id)
            fee_lovelace = signed_tx.transaction_body.fee
            self._backend.submit_tx(signed_tx)
        except Exception as e:
            return _failure(
                operation=operation,
                error=str(e),
                error_type=_classify_error(e),
                nonce_used=nonce_used,
                submitted_at=submitted_at,
                duration_s=round(time.time() - submitted_at, 2),
            )

        confirmed, err, err_type = self._confirm(tx_hash)
        confirmed_at = time.time()

        if not confirmed:
            return _failure(
                operation=operation,
                error=err,
                error_type=err_type,
                nonce_used=nonce_used,
                tx_hash=tx_hash,
                submitted_at=submitted_at,
                duration_s=round(confirmed_at - submitted_at, 2),
            )

        return _success(
            operation=operation,
            tx_hash=tx_hash,
            fee_lovelace=fee_lovelace,
            nonce_used=nonce_used,
            nonce_after=nonce_used + 1,
            submitted_at=submitted_at,
            confirmed_at=confirmed_at,
            extra=extra,
        )

    # ══════════════════════════════════════════════════════════════════════
    # Public: pause
    # ══════════════════════════════════════════════════════════════════════

    def pause(self) -> dict:
        """
        Pause the registry. Authority key required.
        The contract rejects this if already paused.
        """
        try:
            master_utxo, old_datum = self._get_master_utxo()
            ref_utxo = self._get_ref_utxo()
            nonce = old_datum.nonce

            signature = self._sign_ed25519(
                self._authority_key, self._int_to_be(nonce, 8) + b"PAUSE"
            )
            redeemer   = Pause(nonce=nonce, signature=signature)
            new_datum  = self._carry_forward(old_datum, is_paused=AikenTrue())
            master_out = self._build_master_output(new_datum)

            builder = self._base_spend_builder(master_utxo, ref_utxo, redeemer)
            builder.add_output(master_out)

            return self._submit_and_confirm(builder, "pause", nonce)

        except Exception as e:
            return _failure("pause", str(e), _classify_error(e))

    # ══════════════════════════════════════════════════════════════════════
    # Public: resume
    # ══════════════════════════════════════════════════════════════════════

    def resume(self) -> dict:
        """
        Resume the registry. Authority key required.
        The contract rejects this if not paused.
        """
        try:
            master_utxo, old_datum = self._get_master_utxo()
            ref_utxo = self._get_ref_utxo()
            nonce = old_datum.nonce

            signature = self._sign_ed25519(
                self._authority_key, self._int_to_be(nonce, 8) + b"RESUME"
            )
            redeemer   = Resume(nonce=nonce, signature=signature)
            new_datum  = self._carry_forward(old_datum, is_paused=AikenFalse())
            master_out = self._build_master_output(new_datum)

            builder = self._base_spend_builder(master_utxo, ref_utxo, redeemer)
            builder.add_output(master_out)

            return self._submit_and_confirm(builder, "resume", nonce)

        except Exception as e:
            return _failure("resume", str(e), _classify_error(e))

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
    ) -> dict:
        """
        Mint a document token. Operator key required.

        Args:
            cross_chain_global_id: Human-readable global document identifier.
            sha256_hash:           Hex string of the document SHA-256 hash (64 chars).
            upload_date:           ISO 8601 date string e.g. "2026-07-04T00:00:00Z".
            version:               Document version integer.
            token_data:            Metadata dict, JSON-serialized internally.
            is_unique_document:    Counts as a unique document. Default True.
        """
        try:
            # ── Validate inputs ───────────────────────────────────────────
            sha256_hash_bytes = bytes.fromhex(sha256_hash)
            if len(sha256_hash_bytes) != 32:
                return _failure(
                    "mint",
                    f"sha256_hash must be 32 bytes (64 hex chars), got {len(sha256_hash_bytes)}.",
                    ERROR_INVALID_INPUT,
                )

            # ── Fetch state ───────────────────────────────────────────────
            master_utxo, old_datum = self._get_master_utxo()
            ref_utxo = self._get_ref_utxo()
            nonce = old_datum.nonce

            # ── Encode ────────────────────────────────────────────────────
            cross_chain_global_id_bytes = cross_chain_global_id.encode("utf-8")
            upload_date_bytes           = upload_date.encode("utf-8")
            token_data_bytes            = json.dumps(token_data, separators=(",", ":")).encode("utf-8")

            # ── Sign ──────────────────────────────────────────────────────
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

            # ── Asset ─────────────────────────────────────────────────────
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

            master_out = self._build_master_output(new_datum)
            token_out  = TransactionOutput(
                address=self._script_address,
                amount=Value(coin=self.TOKEN_UTXO_FLOOR_LOVELACE, multi_asset=token_multi_asset),
                datum=token_datum,
            )

            builder = self._base_spend_builder(master_utxo, ref_utxo, redeemer)
            builder.add_output(master_out)
            builder.add_output(token_out)
            builder.add_minting_script(script=ref_utxo, redeemer=Redeemer(MintToken()))
            builder.mint = token_multi_asset

            return self._submit_and_confirm(
                builder, "mint", nonce,
                extra={
                    "token_id":             token_id.hex(),
                    "asset_name":           asset_name.hex(),
                    "cross_chain_global_id": cross_chain_global_id,
                    "version":              version,
                    "is_unique_document":   is_unique_document,
                },
            )

        except Exception as e:
            return _failure("mint", str(e), _classify_error(e))

    # ══════════════════════════════════════════════════════════════════════
    # Public: withdraw
    # ══════════════════════════════════════════════════════════════════════

    def withdraw(self, amount_lovelace: int) -> dict:
        """
        Withdraw lovelace from the registry to the owner address. Owner key required.

        Args:
            amount_lovelace: Amount in lovelace to withdraw. Must be positive.
        """
        try:
            if amount_lovelace <= 0:
                return _failure(
                    "withdraw",
                    f"amount_lovelace must be positive, got {amount_lovelace}.",
                    ERROR_INVALID_INPUT,
                )

            master_utxo, old_datum = self._get_master_utxo()
            ref_utxo = self._get_ref_utxo()
            nonce = old_datum.nonce

            signed_payload = (
                self._int_to_be(nonce, 8)
                + b"WITHDRAW"
                + self._int_to_be(amount_lovelace, 8)
            )
            signature = self._sign_ed25519(self._owner_key, signed_payload)

            redeemer   = Withdraw(nonce=nonce, amount=amount_lovelace, signature=signature)
            new_datum  = self._carry_forward(old_datum)
            master_out = self._build_master_output(new_datum)

            # Reconstruct owner address from datum
            pay_cred   = old_datum.owner_address.payment_credential
            owner_addr = Address(
                payment_part=VerificationKeyHash(pay_cred.credential_hash),
                network=Network.TESTNET,
            )
            owner_out = TransactionOutput(address=owner_addr, amount=amount_lovelace)

            builder = self._base_spend_builder(master_utxo, ref_utxo, redeemer)
            builder.add_output(master_out)
            builder.add_output(owner_out)

            return self._submit_and_confirm(
                builder, "withdraw", nonce,
                extra={
                    "amount_lovelace": amount_lovelace,
                    "amount_ada":      round(amount_lovelace / 1_000_000, 6),
                    "owner_address":   str(owner_addr),
                },
            )

        except Exception as e:
            return _failure("withdraw", str(e), _classify_error(e))

    # ══════════════════════════════════════════════════════════════════════
    # Public: rotate_key
    # ══════════════════════════════════════════════════════════════════════

    def rotate_key(
        self,
        key_type: Literal["authority", "operator", "owner"],
        new_public_key_hex: str,
    ) -> dict:
        """
        Rotate one of the three permission keys. Authority key required.

        Args:
            key_type:           "authority", "operator", or "owner".
            new_public_key_hex: Hex string of the new 32-byte Ed25519 public key.
        """
        try:
            new_key = bytes.fromhex(new_public_key_hex)
            if len(new_key) != 32:
                return _failure(
                    "rotate_key",
                    f"new_public_key_hex must be 32 bytes (64 hex chars), got {len(new_key)}.",
                    ERROR_INVALID_INPUT,
                )

            key_type_lower = key_type.lower()
            if key_type_lower == "authority":
                key_tag, key_type_str = AuthorityKeyTag(), b"AUTHORITY"
            elif key_type_lower == "operator":
                key_tag, key_type_str = OperatorKeyTag(), b"OPERATOR"
            elif key_type_lower == "owner":
                key_tag, key_type_str = OwnerKeyTag(), b"OWNER"
            else:
                return _failure(
                    "rotate_key",
                    f"key_type must be 'authority', 'operator', or 'owner', got {key_type!r}.",
                    ERROR_INVALID_INPUT,
                )

            master_utxo, old_datum = self._get_master_utxo()
            ref_utxo = self._get_ref_utxo()
            nonce = old_datum.nonce

            signed_payload = (
                self._int_to_be(nonce, 8) + b"ROTATE" + key_type_str + new_key
            )
            signature = self._sign_ed25519(self._authority_key, signed_payload)

            redeemer = RotateKey(
                nonce=nonce, key_type=key_tag, new_key=new_key, signature=signature
            )

            if key_type_lower == "authority":
                new_datum = self._carry_forward(old_datum, authority_key=new_key)
            elif key_type_lower == "operator":
                new_datum = self._carry_forward(old_datum, operator_key=new_key)
            else:
                new_datum = self._carry_forward(old_datum, owner_key=new_key)

            master_out = self._build_master_output(new_datum)

            builder = self._base_spend_builder(master_utxo, ref_utxo, redeemer)
            builder.add_output(master_out)

            return self._submit_and_confirm(
                builder, "rotate_key", nonce,
                extra={
                    "key_type":     key_type_lower,
                    "new_key_hex":  new_public_key_hex,
                },
            )

        except Exception as e:
            return _failure("rotate_key", str(e), _classify_error(e))

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
    ) -> dict:
        """
        Seal a permanent forward link to a successor deployment. Authority key required.
        The contract rejects this if the forward link slot is already set.

        Args:
            next_script_address: Bech32 address of the successor script.
            next_policy_id:      Hex string of the successor policy ID.
            link_reason:         Human-readable reason for the migration.
            linked_at:           Timestamp or epoch integer recorded in the link.
            instructions:        Human-readable migration instructions.
        """
        try:
            master_utxo, old_datum = self._get_master_utxo()
            ref_utxo = self._get_ref_utxo()
            nonce = old_datum.nonce

            next_script_address_bytes = next_script_address.encode("utf-8")
            next_policy_id_bytes      = bytes.fromhex(next_policy_id)
            link_reason_bytes         = link_reason.encode("utf-8")
            instructions_bytes        = instructions.encode("utf-8")

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
            new_datum  = self._carry_forward(old_datum, forward_link=SomeChainLink(value=chain_link))
            master_out = self._build_master_output(new_datum)

            builder = self._base_spend_builder(master_utxo, ref_utxo, redeemer)
            builder.add_output(master_out)

            return self._submit_and_confirm(
                builder, "link_forward", nonce,
                extra={
                    "next_script_address": next_script_address,
                    "next_policy_id":      next_policy_id,
                    "link_reason":         link_reason,
                    "linked_at":           linked_at,
                },
            )

        except Exception as e:
            return _failure("link_forward", str(e), _classify_error(e))

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
    ) -> dict:
        """
        Establish a permanent backward link to a predecessor deployment. Authority key required.
        The contract rejects this if the backward link slot is already set.

        Args:
            prev_script_address: Bech32 address of the predecessor script.
            prev_policy_id:      Hex string of the predecessor policy ID.
            link_reason:         Human-readable reason for the linkage.
            linked_at:           Timestamp or epoch integer recorded in the link.
            instructions:        Human-readable notes about the predecessor.
        """
        try:
            master_utxo, old_datum = self._get_master_utxo()
            ref_utxo = self._get_ref_utxo()
            nonce = old_datum.nonce

            prev_script_address_bytes = prev_script_address.encode("utf-8")
            prev_policy_id_bytes      = bytes.fromhex(prev_policy_id)
            link_reason_bytes         = link_reason.encode("utf-8")
            instructions_bytes        = instructions.encode("utf-8")

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
            new_datum  = self._carry_forward(old_datum, backward_link=SomeChainLink(value=chain_link))
            master_out = self._build_master_output(new_datum)

            builder = self._base_spend_builder(master_utxo, ref_utxo, redeemer)
            builder.add_output(master_out)

            return self._submit_and_confirm(
                builder, "link_backward", nonce,
                extra={
                    "prev_script_address": prev_script_address,
                    "prev_policy_id":      prev_policy_id,
                    "link_reason":         link_reason,
                    "linked_at":           linked_at,
                },
            )

        except Exception as e:
            return _failure("link_backward", str(e), _classify_error(e))

    # ══════════════════════════════════════════════════════════════════════
    # Public: get_master_state
    # ══════════════════════════════════════════════════════════════════════

    def get_master_state(self) -> dict:
        """
        Read the current master registry state. No keys required.
        Returns a plain dict. Safe to call at any time.
        """
        utxo, datum = self._get_master_utxo()

        def _link_to_dict(link) -> Optional[dict]:
            if isinstance(link, SomeChainLink):
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
            "utxo":                       f"{utxo.input.transaction_id}#{utxo.input.index}",
            "nonce":                      datum.nonce,
            "is_paused":                  isinstance(datum.is_paused, AikenTrue),
            "total_token_count":          datum.stats.total_token_count,
            "total_unique_documents":     datum.stats.total_unique_documents,
            "last_minted_at":             datum.stats.last_minted_at,
            "last_cross_chain_global_id": datum.stats.last_cross_chain_global_id.decode("utf-8", errors="replace"),
            "last_cardano_asset_id":      datum.stats.last_cardano_asset_id.hex(),
            "policy_id":                  self._policy_id.hex(),
            "asset_name_prefix":          datum.asset_name_prefix.decode("utf-8", errors="replace"),
            "authority_key":              datum.authority_key.hex(),
            "operator_key":               datum.operator_key.hex(),
            "owner_key":                  datum.owner_key.hex(),
            "forward_link":               _link_to_dict(datum.forward_link),
            "backward_link":              _link_to_dict(datum.backward_link),
        }