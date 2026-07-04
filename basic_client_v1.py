"""
bare_client.py - Absolute minimal Cardano testnet write client.

Purpose: isolate whether reliable transaction confirmation is possible at
all on Cardano/Blockfrost preprod, with zero abstraction layers that could
hide or introduce bugs. This is NOT meant to be reused or extended - it is
a diagnostic instrument.

Design rules followed exactly:
  - 3 keys only: operator_key, authority_key, funding_signing_key
  - Deployment info + keys loaded ONCE at __init__, held for object lifetime
  - Only 3 methods: pause(), resume(), mint()
  - Each method is fully self-contained: fetch state -> build -> sign ->
    submit -> poll for confirmation -> return. No shared write helper
    between them beyond raw pycardano calls. No retry logic. No error
    classification. No masking.
  - Real Blockfrost evaluator used exactly as pycardano provides it -
    no overrides, no hardcoded execution units.
  - Master UTXO state fetched via a SINGLE call to Blockfrost's address
    UTXO endpoint per invocation - no double-fetch.
  - Master output lovelace amount computed via pycardano's real
    min_lovelace_post_alonzo, not a hardcoded guess - a hardcoded 3 ADA
    floor caused BabbageOutputTooSmallUTxO once the datum grew past what
    that guess covered.
  - Returns a plain (success: bool, tx_hash: str|None, error: str|None)
    tuple. Nothing else.
"""

import json
import time
from pathlib import Path

from pycardano import (
    Address, Asset, AssetName, BlockFrostChainContext, MultiAsset,
    Network, PaymentSigningKey, PlutusV3Script, Redeemer, ScriptHash,
    TransactionBuilder, TransactionOutput, Value,
)
from blockfrost import ApiUrls, ApiError

try:
    from pycardano import min_lovelace_post_alonzo as _min_lovelace
except ImportError:
    from pycardano.utils import min_lovelace_post_alonzo as _min_lovelace

from CardanoDeployer.cardano_types import (
    AikenFalse, AikenTrue, MasterDatum, OutputReference, RegistryStats,
)
from test_types import MintDocument, Pause, Resume, MintToken, TokenDatum


class BareClient:
    def __init__(
        self,
        deployment_json_path: str,
        perm_keys_json_path: str,
        funding_signing_key_cbor_hex: str,
    ):
        # ── Load deployment info ONCE ────────────────────────────────
        deployment = json.loads(Path(deployment_json_path).read_text())
        self.policy_id = bytes.fromhex(deployment["contract"]["policy_id"])
        self.script_address = Address.from_primitive(deployment["contract"]["script_address"])
        self.beacon_asset_name = bytes.fromhex(deployment["beacon"]["asset_name_hex"])

        blueprint = json.loads(
            Path(deployment["contract"]["bootstrap_generated_plutus_path"]).read_text()
        )
        spend_validator = next(
            v for v in blueprint["validators"] if v["title"].endswith(".spend")
        )
        self.script = PlutusV3Script(bytes.fromhex(spend_validator["compiledCode"]))

        # ── Load keys ONCE ────────────────────────────────────────────
        perm_keys = json.loads(Path(perm_keys_json_path).read_text())
        self.operator_key = bytes.fromhex(perm_keys["operator"]["private_key_hex"])
        self.authority_key = bytes.fromhex(perm_keys["authority"]["private_key_hex"])

        self.funding_key = PaymentSigningKey.from_cbor(funding_signing_key_cbor_hex)
        self.funding_address = Address(
            payment_part=self.funding_key.to_verification_key().hash(),
            network=Network.TESTNET,
        )

        # ── Blockfrost context - real, unmodified pycardano ──────────
        self.context = BlockFrostChainContext(
            project_id="preprodviqzO4lW7gcYXeQoxtAg50qneXkq00dW",
            network=Network.TESTNET,
            base_url=ApiUrls.preprod.value,
        )

        self.TTL_BUFFER_SLOTS = 200
        self.MASTER_UTXO_FLOOR_LOVELACE = 3_000_000
        self.TOKEN_UTXO_FLOOR_LOVELACE = 3_000_000
        self.COLLATERAL_MIN_LOVELACE = 5_000_000
        self.CONFIRMATION_TIMEOUT_S = 180.0
        self.CONFIRMATION_POLL_INTERVAL_S = 5.0

    # ────────────────────────────────────────────────────────────────
    # Internal: single-fetch master state read (no double-fetch)
    # ────────────────────────────────────────────────────────────────

    def _get_master_utxo(self):
        """
        Single Blockfrost call. Returns (utxo, datum) for whichever UTXO
        at script_address holds the beacon token. Raises if not found or
        if the datum can't be decoded - no silent fallback, no retry.
        """
        utxos = self.context.utxos(self.script_address)
        for u in utxos:
            qty = u.output.amount.multi_asset.get(ScriptHash(self.policy_id), {}).get(
                AssetName(self.beacon_asset_name)
            )
            if qty == 1:
                if u.output.datum is None:
                    raise RuntimeError("Master UTXO found but has no datum attached.")
                datum = MasterDatum.from_cbor(u.output.datum.cbor)
                return u, datum
        raise RuntimeError("No UTXO at script address holds the beacon token.")

    def _build_master_output(self, new_datum: MasterDatum) -> TransactionOutput:
        """
        Builds the master UTXO output with a correctly-sized lovelace
        amount - uses pycardano's real min_lovelace_post_alonzo rather
        than a hardcoded guess, since the required minimum grows with
        datum size (forward_link/backward_link/stats all affect this).
        """
        beacon_multi_asset = MultiAsset({
            ScriptHash(self.policy_id): Asset({AssetName(self.beacon_asset_name): 1})
        })
        output = TransactionOutput(
            address=self.script_address,
            amount=Value(coin=self.MASTER_UTXO_FLOOR_LOVELACE, multi_asset=beacon_multi_asset),
            datum=new_datum,
        )
        required = max(self.MASTER_UTXO_FLOOR_LOVELACE, _min_lovelace(output, self.context))
        output.amount = Value(coin=required, multi_asset=beacon_multi_asset)
        return output

    def _attach_collateral(self, builder: TransactionBuilder) -> None:
        """Single Blockfrost call for funding address UTXOs, pick smallest ADA-only >= floor."""
        candidates = [
            u for u in self.context.utxos(self.funding_address)
            if len(u.output.amount.multi_asset) == 0
            and u.output.amount.coin >= self.COLLATERAL_MIN_LOVELACE
        ]
        if not candidates:
            raise RuntimeError("No ADA-only funding UTXO clears the collateral floor.")
        builder.collaterals.append(min(candidates, key=lambda u: u.output.amount.coin))

    def _confirm(self, tx_hash: str):
        """
        Polls Blockfrost's /txs/{hash}/utxos endpoint until it succeeds
        or the timeout is hit. No retry-on-failure logic beyond this
        simple poll loop - if it never confirms within the timeout,
        that IS the answer we're trying to measure.
        """
        deadline = time.monotonic() + self.CONFIRMATION_TIMEOUT_S
        last_err = None
        while time.monotonic() < deadline:
            try:
                result = self.context.api.transaction_utxos(hash=tx_hash)
                if getattr(result, "outputs", None):
                    return True, None
            except ApiError as e:
                last_err = str(e)
            time.sleep(self.CONFIRMATION_POLL_INTERVAL_S)
        return False, f"Confirmation timeout after {self.CONFIRMATION_TIMEOUT_S}s. Last error: {last_err}"

    @staticmethod
    def _sign_ed25519(private_key_32: bytes, message: bytes) -> bytes:
        from nacl.signing import SigningKey
        return SigningKey(private_key_32).sign(message).signature

    @staticmethod
    def _int_to_be_bytes(value: int, length: int) -> bytes:
        return value.to_bytes(length, byteorder="big", signed=False)

    @staticmethod
    def _carry_forward(old: MasterDatum, **overrides) -> MasterDatum:
        fields = dict(
            authority_key=old.authority_key, operator_key=old.operator_key, owner_key=old.owner_key,
            owner_address=old.owner_address, nonce=old.nonce + 1, is_paused=old.is_paused,
            policy_id=old.policy_id, asset_name_prefix=old.asset_name_prefix,
            forward_link=old.forward_link, backward_link=old.backward_link, stats=old.stats,
        )
        fields.update(overrides)
        return MasterDatum(**fields)

    # ────────────────────────────────────────────────────────────────
    # PAUSE - fully self-contained
    # ────────────────────────────────────────────────────────────────

    def pause(self):
        try:
            master_utxo, old_datum = self._get_master_utxo()

            nonce = old_datum.nonce
            signature = self._sign_ed25519(
                self.authority_key, self._int_to_be_bytes(nonce, 8) + b"PAUSE"
            )
            redeemer = Pause(nonce=nonce, signature=signature)
            new_datum = self._carry_forward(old_datum, is_paused=AikenTrue())
            master_output = self._build_master_output(new_datum)

            builder = TransactionBuilder(
                self.context, ttl=self.context.last_block_slot + self.TTL_BUFFER_SLOTS
            )
            builder.add_input_address(self.funding_address)
            builder.add_script_input(
                utxo=master_utxo, script=self.script, redeemer=Redeemer(redeemer)
            )
            self._attach_collateral(builder)
            builder.add_output(master_output)

            signed_tx = builder.build_and_sign(
                signing_keys=[self.funding_key], change_address=self.funding_address
            )
            tx_hash = str(signed_tx.id)
            self.context.submit_tx(signed_tx)

            confirmed, err = self._confirm(tx_hash)
            return confirmed, tx_hash, err

        except Exception as e:
            return False, None, str(e)

    # ────────────────────────────────────────────────────────────────
    # RESUME - fully self-contained
    # ────────────────────────────────────────────────────────────────

    def resume(self):
        try:
            master_utxo, old_datum = self._get_master_utxo()

            nonce = old_datum.nonce
            signature = self._sign_ed25519(
                self.authority_key, self._int_to_be_bytes(nonce, 8) + b"RESUME"
            )
            redeemer = Resume(nonce=nonce, signature=signature)
            new_datum = self._carry_forward(old_datum, is_paused=AikenFalse())
            master_output = self._build_master_output(new_datum)

            builder = TransactionBuilder(
                self.context, ttl=self.context.last_block_slot + self.TTL_BUFFER_SLOTS
            )
            builder.add_input_address(self.funding_address)
            builder.add_script_input(
                utxo=master_utxo, script=self.script, redeemer=Redeemer(redeemer)
            )
            self._attach_collateral(builder)
            builder.add_output(master_output)

            signed_tx = builder.build_and_sign(
                signing_keys=[self.funding_key], change_address=self.funding_address
            )
            tx_hash = str(signed_tx.id)
            self.context.submit_tx(signed_tx)

            confirmed, err = self._confirm(tx_hash)
            return confirmed, tx_hash, err

        except Exception as e:
            return False, None, str(e)

    # ────────────────────────────────────────────────────────────────
    # MINT - fully self-contained
    # ────────────────────────────────────────────────────────────────

    def mint(self, cross_chain_global_id: bytes, sha256_hash: bytes, upload_date: bytes,
              version: int, token_data: bytes):
        try:
            master_utxo, old_datum = self._get_master_utxo()

            nonce = old_datum.nonce
            signed_payload = (
                self._int_to_be_bytes(nonce, 8) + cross_chain_global_id + sha256_hash
                + self._int_to_be_bytes(version, 4)
            )
            signature = self._sign_ed25519(self.operator_key, signed_payload)

            redeemer = MintDocument(
                nonce=nonce, cross_chain_global_id=cross_chain_global_id, sha256_hash=sha256_hash,
                upload_date=upload_date, version=version, token_data=token_data,
                is_unique_document=AikenTrue(), valid_lower_bound=nonce, signature=signature,
            )

            asset_name = old_datum.asset_name_prefix + self._int_to_be_bytes(nonce, 4)
            token_id = self.policy_id + asset_name

            new_datum = self._carry_forward(
                old_datum,
                stats=RegistryStats(
                    total_token_count=old_datum.stats.total_token_count + 1,
                    total_unique_documents=old_datum.stats.total_unique_documents + 1,
                    last_minted_at=nonce,
                    last_cross_chain_global_id=cross_chain_global_id,
                    last_cardano_asset_id=token_id,
                ),
            )

            token_datum = TokenDatum(
                cardano_asset_id=token_id, cross_chain_global_id=cross_chain_global_id,
                registry_address=b"", policy_id=self.policy_id,
                source_registry_master_utxo_reference=OutputReference(
                    transaction_id=master_utxo.input.transaction_id.payload,
                    output_index=master_utxo.input.index,
                ),
                sha256_hash=sha256_hash, upload_date=upload_date, version=version, token_data=token_data,
            )

            token_multi_asset = MultiAsset({ScriptHash(self.policy_id): Asset({AssetName(asset_name): 1})})
            token_output = TransactionOutput(
                address=self.script_address,
                amount=Value(coin=self.TOKEN_UTXO_FLOOR_LOVELACE, multi_asset=token_multi_asset),
                datum=token_datum,
            )

            master_output = self._build_master_output(new_datum)

            builder = TransactionBuilder(
                self.context, ttl=self.context.last_block_slot + self.TTL_BUFFER_SLOTS
            )
            builder.add_input_address(self.funding_address)
            builder.add_script_input(
                utxo=master_utxo, script=self.script, redeemer=Redeemer(redeemer)
            )
            self._attach_collateral(builder)
            builder.add_output(master_output)
            builder.add_output(token_output)
            builder.add_minting_script(self.script, Redeemer(MintToken()))
            builder.mint = token_multi_asset

            signed_tx = builder.build_and_sign(
                signing_keys=[self.funding_key], change_address=self.funding_address
            )
            tx_hash = str(signed_tx.id)
            self.context.submit_tx(signed_tx)

            confirmed, err = self._confirm(tx_hash)
            return confirmed, tx_hash, err

        except Exception as e:
            return False, None, str(e)