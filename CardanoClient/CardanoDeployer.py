"""
CardanoDeployer.py - ZPEPG Cardano contract deployment utility.

Self-contained: all Blockfrost context, confirmation polling, blueprint
parameterization, and type encoding live in this file. No dependency on
CardanoClient.py.

Three deployment modes:

  1. FULL DEPLOYMENT (default)
     Runs the complete pipeline: genesis tx + reference script tx.
     Produces deployment.json and deployment_ref_<timestamp>.json.

  2. GENESIS ONLY (--genesis-only)
     Only runs the genesis transaction. Produces deployment.json.
     Use when you want to post the reference script later separately.

  3. UPDATE CONTRACT REFERENCE (--update-contract-reference)
     Reads an existing deployment.json, posts the compiled script as a
     new reference script UTXO, produces updated_deployment_<timestamp>.json.
     Use when the reference UTXO needs to be reposted without redeploying.

CLI modes for UTXO selection:

  --genesis-ref <hash#index>   Non-interactive: use this UTXO as genesis input.
  (omitted)                    Interactive: UTXO picker runs.
  --list-utxos                 Print UTXOs at the funding address and exit.

Usage examples:

  # Full deployment, interactive UTXO picker
  python3.12 CardanoDeployer.py --network preprod --funding-key <cbor> --perm-keys perm_keys.json --source-blueprint plutus.json

  # Full deployment, specific UTXO
  python3.12 CardanoDeployer.py --network preprod --funding-key <cbor> --perm-keys perm_keys.json --source-blueprint plutus.json --genesis-ref abc123...#1

  # Genesis only
  python3.12 CardanoDeployer.py --network preprod --funding-key <cbor> --perm-keys perm_keys.json --source-blueprint plutus.json --genesis-only

  # Update contract reference
  python3.12 CardanoDeployer.py --network preprod --funding-key <cbor> --deployment-json testnet_deployment.json --update-contract-reference

  # List UTXOs
  python3.12 CardanoDeployer.py --network preprod --funding-key <cbor> --list-utxos
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from blockfrost import ApiError, ApiUrls
from pycardano import (
    Address, Asset, AssetName, BlockFrostChainContext, MultiAsset,
    Network, PaymentSigningKey, PlutusV2Script, PlutusV3Script,
    Redeemer, ScriptHash, TransactionBuilder, TransactionOutput,
    UTxO, Value, VerificationKeyHash,
)

from CardanoUtils import (
    AikenFalse, MasterDatum, MintBeacon, NoneChainLink,
    OutputReference, PlutusAddress, RegistryStats,
    SomeStakeCredential, InlineStakeCredential,
    VerificationKeyCredential, NoneStakeCredential,
)
from CardanoUtils import AikenBlueprint

try:
    from pycardano import min_lovelace_post_alonzo as _min_lovelace
except ImportError:
    from pycardano.utils import min_lovelace_post_alonzo as _min_lovelace


# ══════════════════════════════════════════════════════════════════════════════
# Constants
# ══════════════════════════════════════════════════════════════════════════════

BEACON_ASSET_NAME          = b"ZPEPG-BEACON"
REGISTRY_ASSET_NAME_PREFIX = b"ZPEPG-ARCHIVE-DOC"

MASTER_UTXO_FLOOR_LOVELACE  = 3_000_000
REF_SCRIPT_UTXO_LOVELACE    = 70_000_000   # ~32.6 ADA minimum for 7KB script
COLLATERAL_MIN_LOVELACE     = 5_000_000
TTL_BUFFER_SLOTS            = 500

CONFIRMATION_TIMEOUT_S       = 300.0
CONFIRMATION_POLL_INTERVAL_S = 5.0
ADDRESS_CATCHUP_TIMEOUT_S    = 30.0
ADDRESS_CATCHUP_POLL_S       = 2.0
FUNDING_CATCHUP_TIMEOUT_S    = 30.0
FUNDING_CATCHUP_POLL_S       = 2.0

BLOCKFROST_PROJECT_IDS = {
    "preprod": "preprodviqzO4lW7gcYXeQoxtAg50qneXkq00dW",
    "mainnet": None,  # fill in when needed
}

NETWORK_MAP = {
    "preprod": (Network.TESTNET, ApiUrls.preprod.value),
    "mainnet": (Network.MAINNET, ApiUrls.mainnet.value),
}


# ══════════════════════════════════════════════════════════════════════════════
# Internal helpers
# ══════════════════════════════════════════════════════════════════════════════

def _load_context(network: str) -> BlockFrostChainContext:
    if network not in NETWORK_MAP:
        raise ValueError(f"Unknown network {network!r}. Choose: {list(NETWORK_MAP)}")
    project_id = BLOCKFROST_PROJECT_IDS.get(network)
    if not project_id:
        raise ValueError(f"No Blockfrost project ID configured for {network}.")
    pycardano_network, base_url = NETWORK_MAP[network]
    return BlockFrostChainContext(
        project_id=project_id,
        network=pycardano_network,
        base_url=base_url,
    )


def _load_funding_key(cbor_hex: str, network: Network) -> tuple[PaymentSigningKey, Address]:
    key = PaymentSigningKey.from_cbor(cbor_hex)
    address = Address(payment_part=key.to_verification_key().hash(), network=network)
    return key, address


def _load_perm_keys(perm_keys_path: str) -> tuple[bytes, bytes, bytes]:
    data = json.loads(Path(perm_keys_path).read_text())
    return (
        bytes.fromhex(data["authority"]["public_key_hex"]),
        bytes.fromhex(data["operator"]["public_key_hex"]),
        bytes.fromhex(data["owner"]["public_key_hex"]),
    )


def _script_from_blueprint(blueprint: dict) -> tuple:
    """Returns (script, compiled_code_hex) from a parameterized blueprint."""
    spend_validator = next(
        v for v in blueprint["validators"] if v["title"].endswith(".spend")
    )
    compiled_hex = spend_validator["compiledCode"]
    preamble = blueprint.get("preamble", {})
    version  = preamble.get("plutusVersion", "v2").lower().strip()
    compiled_bytes = bytes.fromhex(compiled_hex)
    script = PlutusV3Script(compiled_bytes) if version == "v3" else PlutusV2Script(compiled_bytes)
    return script, compiled_hex


def _attach_collateral(builder: TransactionBuilder, context: BlockFrostChainContext, funding_address: Address) -> None:
    candidates = [
        u for u in context.utxos(funding_address)
        if not u.output.amount.multi_asset
        and u.output.amount.coin >= COLLATERAL_MIN_LOVELACE
    ]
    if not candidates:
        raise RuntimeError(
            f"No ADA-only UTXO >= {COLLATERAL_MIN_LOVELACE} lovelace at {funding_address} for collateral."
        )
    builder.collaterals.append(min(candidates, key=lambda u: u.output.amount.coin))


def _confirm(context: BlockFrostChainContext, funding_address: Address,
             script_address: Address, tx_hash: str) -> tuple[bool, Optional[str]]:
    """Three-stage confirmation: tx-level, script address, funding address."""
    deadline = time.monotonic() + CONFIRMATION_TIMEOUT_S
    last_err = None

    # Stage 1
    print(f"  [confirm] Stage 1: waiting for tx {tx_hash[:16]}...")
    while time.monotonic() < deadline:
        try:
            result = context.api.transaction_utxos(hash=tx_hash)
            if getattr(result, "outputs", None):
                print("  [confirm] Stage 1: confirmed.")
                break
        except ApiError as e:
            last_err = str(e)
        time.sleep(CONFIRMATION_POLL_INTERVAL_S)
    else:
        return False, f"Stage 1 timeout after {CONFIRMATION_TIMEOUT_S}s. Last: {last_err}"

    # Stage 2: script address
    print("  [confirm] Stage 2: waiting for script address catchup...")
    addr_deadline = time.monotonic() + ADDRESS_CATCHUP_TIMEOUT_S
    while time.monotonic() < addr_deadline:
        try:
            utxos = context.utxos(script_address)
            if any(str(u.input.transaction_id) == tx_hash for u in utxos):
                print("  [confirm] Stage 2: caught up.")
                break
        except Exception as e:
            last_err = str(e)
        time.sleep(ADDRESS_CATCHUP_POLL_S)
    else:
        return False, f"Stage 2 timeout after {ADDRESS_CATCHUP_TIMEOUT_S}s. Last: {last_err}"

    # Stage 3: funding address
    print("  [confirm] Stage 3: waiting for funding address catchup...")
    fund_deadline = time.monotonic() + FUNDING_CATCHUP_TIMEOUT_S
    while time.monotonic() < fund_deadline:
        try:
            utxos = context.utxos(funding_address)
            if any(str(u.input.transaction_id) == tx_hash for u in utxos):
                print("  [confirm] Stage 3: caught up.")
                return True, None
        except Exception as e:
            last_err = str(e)
        time.sleep(FUNDING_CATCHUP_POLL_S)

    return False, f"Stage 3 timeout after {FUNDING_CATCHUP_TIMEOUT_S}s. Last: {last_err}"


def _timestamp_str() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


# ══════════════════════════════════════════════════════════════════════════════
# CardanoDeployer
# ══════════════════════════════════════════════════════════════════════════════

class CardanoDeployer:
    """
    Self-contained ZPEPG contract deployment utility.

    Handles the full deployment pipeline:
      1. deploy_genesis()          - parameterize + beacon mint + master UTXO
      2. deploy_contract_script()  - post compiled script as reference UTXO
      3. deploy_contract()         - runs both in sequence

    All three methods return a result dict with success/error info and
    the paths of any JSON files written.
    """

    def __init__(
        self,
        network: str,
        funding_signing_key_cbor: str,
        perm_keys_path: Optional[str] = None,
        source_blueprint_path: Optional[str] = None,
    ):
        """
        Args:
            network:                  "preprod" or "mainnet".
            funding_signing_key_cbor: Raw cborHex of the funding payment key.
            perm_keys_path:           Path to perm_keys.json. Required for genesis.
            source_blueprint_path:    Path to unparameterized plutus.json. Required for genesis.
        """
        self._network_str        = network
        self._pycardano_network, self._base_url = NETWORK_MAP[network]
        self._context            = _load_context(network)
        self._funding_key, self._funding_address = _load_funding_key(
            funding_signing_key_cbor, self._pycardano_network
        )
        self._perm_keys_path          = perm_keys_path
        self._source_blueprint_path   = source_blueprint_path

    # ══════════════════════════════════════════════════════════════════════
    # Public: list UTxOs
    # ══════════════════════════════════════════════════════════════════════

    def list_utxos(self) -> list[dict]:
        """Return UTxOs at the funding address as a list of dicts."""
        utxos = self._context.utxos(self._funding_address)
        return [
            {
                "tx_hash":      str(u.input.transaction_id),
                "output_index": u.input.index,
                "lovelace":     u.output.amount.coin,
                "ada":          round(u.output.amount.coin / 1_000_000, 6),
                "has_tokens":   bool(u.output.amount.multi_asset),
                "ref":          f"{u.input.transaction_id}#{u.input.index}",
            }
            for u in utxos
        ]

    # ══════════════════════════════════════════════════════════════════════
    # Public: deploy_genesis
    # ══════════════════════════════════════════════════════════════════════

    def deploy_genesis(
        self,
        genesis_utxo_ref: Optional[str] = None,
        output_blueprint_path: str = "bootstrap_generated_plutus.json",
        deployment_json_path: str = "deployment.json",
    ) -> dict:
        """
        Run the genesis transaction:
          - Parameterize archive_registry with genesis UTXO + beacon asset name
          - Spend the genesis UTXO, mint the beacon, create the master UTXO
          - Write deployment.json and the parameterized blueprint

        Args:
            genesis_utxo_ref:      "txhash#index". If None, auto-selects largest
                                   plain-ADA UTXO > 5 ADA at the funding address.
            output_blueprint_path: Where to write the parameterized plutus.json.
            deployment_json_path:  Where to write deployment.json.

        Returns:
            Result dict with success, tx_hash, policy_id, script_address,
            deployment_json_path, error.
        """
        if not self._perm_keys_path:
            return {"success": False, "error": "perm_keys_path required for genesis."}
        if not self._source_blueprint_path:
            return {"success": False, "error": "source_blueprint_path required for genesis."}

        try:
            authority_key, operator_key, owner_key = _load_perm_keys(self._perm_keys_path)

            # ── Select genesis UTXO ──────────────────────────────────────
            if genesis_utxo_ref:
                tx_hash_str, idx_str = genesis_utxo_ref.split("#")
                idx = int(idx_str)
                candidates = [
                    u for u in self._context.utxos(self._funding_address)
                    if str(u.input.transaction_id) == tx_hash_str
                    and u.input.index == idx
                ]
                if not candidates:
                    return {"success": False, "error": f"UTXO {genesis_utxo_ref} not found at funding address."}
                genesis_utxo = candidates[0]
            else:
                candidates = [
                    u for u in self._context.utxos(self._funding_address)
                    if not u.output.amount.multi_asset
                    and u.output.amount.coin > 5_000_000
                ]
                if not candidates:
                    return {"success": False, "error": "No plain-ADA UTXO > 5 ADA found at funding address."}
                genesis_utxo = max(candidates, key=lambda u: u.output.amount.coin)

            print(f"  Genesis UTXO: {genesis_utxo.input.transaction_id}#{genesis_utxo.input.index}")

            # ── Parameterize ─────────────────────────────────────────────
            genesis_ref = OutputReference(
                transaction_id=genesis_utxo.input.transaction_id.payload,
                output_index=genesis_utxo.input.index,
            )
            print(f"  Parameterizing blueprint...")
            applied = AikenBlueprint.apply_parameters(
                genesis_ref=genesis_ref,
                beacon_asset_name=BEACON_ASSET_NAME,
                source_blueprint_path=self._source_blueprint_path,
                output_blueprint_path=output_blueprint_path,
            )
            policy_id    = bytes.fromhex(applied.policy_id_hex)
            script_address = Address(
                payment_part=ScriptHash(policy_id),
                network=self._pycardano_network,
            )
            blueprint = json.loads(Path(output_blueprint_path).read_text())
            script, _ = _script_from_blueprint(blueprint)

            print(f"  Policy ID:      {applied.policy_id_hex}")
            print(f"  Script address: {script_address}")

            # ── Build owner address (PlutusAddress) ──────────────────────
            payment_cred = VerificationKeyCredential(bytes(self._funding_address.payment_part))
            if self._funding_address.staking_part is not None:
                stake_cred = SomeStakeCredential(
                    InlineStakeCredential(
                        VerificationKeyCredential(bytes(self._funding_address.staking_part))
                    )
                )
            else:
                stake_cred = NoneStakeCredential()
            owner_address = PlutusAddress(
                payment_credential=payment_cred,
                stake_credential=stake_cred,
            )

            # ── Genesis datum ─────────────────────────────────────────────
            genesis_datum = MasterDatum(
                authority_key=authority_key,
                operator_key=operator_key,
                owner_key=owner_key,
                owner_address=owner_address,
                nonce=0,
                is_paused=AikenFalse(),
                policy_id=policy_id,
                asset_name_prefix=REGISTRY_ASSET_NAME_PREFIX,
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

            beacon_multi_asset = MultiAsset({
                ScriptHash(policy_id): Asset({AssetName(BEACON_ASSET_NAME): 1})
            })

            # ── Build tx ──────────────────────────────────────────────────
            builder = TransactionBuilder(
                self._context,
                ttl=self._context.last_block_slot + TTL_BUFFER_SLOTS,
            )
            builder.add_input(genesis_utxo)
            builder.add_input_address(self._funding_address)
            builder.add_minting_script(script, Redeemer(MintBeacon()))
            builder.mint = beacon_multi_asset
            builder.add_output(TransactionOutput(
                address=script_address,
                amount=Value(coin=MASTER_UTXO_FLOOR_LOVELACE, multi_asset=beacon_multi_asset),
                datum=genesis_datum,
            ))

            print("  Building and signing genesis transaction...")
            signed_tx = builder.build_and_sign(
                signing_keys=[self._funding_key],
                change_address=self._funding_address,
            )
            tx_hash = str(signed_tx.id)

            # ── Write deployment.json before submitting ───────────────────
            record = {
                "network":                      self._network_str,
                "deployed_from_wallet_address": str(self._funding_address),
                "transaction_hash":             tx_hash,
                "genesis_transaction_hash":     genesis_utxo.input.transaction_id.payload.hex(),
                "genesis_output_index":         genesis_utxo.input.index,
                "contract": {
                    "policy_id":                      applied.policy_id_hex,
                    "script_address":                 str(script_address),
                    "bootstrap_generated_plutus_path": str(output_blueprint_path),
                },
                "beacon": {
                    "asset_name_hex":  BEACON_ASSET_NAME.hex(),
                    "asset_name_utf8": BEACON_ASSET_NAME.decode("utf-8"),
                },
            }
            Path(deployment_json_path).write_text(json.dumps(record, indent=2))
            print(f"  deployment.json written: {deployment_json_path}")

            # ── Submit ────────────────────────────────────────────────────
            print(f"  Submitting genesis tx: {tx_hash}")
            self._context.submit_tx(signed_tx)

            confirmed, err = _confirm(
                self._context, self._funding_address, script_address, tx_hash
            )
            if not confirmed:
                return {
                    "success": False,
                    "error": f"Genesis tx submitted but confirmation failed: {err}",
                    "tx_hash": tx_hash,
                    "deployment_json_path": str(deployment_json_path),
                    "note": "deployment.json was written before submission — tx may still confirm.",
                }

            print(f"  Genesis confirmed.")
            return {
                "success":               True,
                "tx_hash":               tx_hash,
                "policy_id":             applied.policy_id_hex,
                "script_address":        str(script_address),
                "deployment_json_path":  str(deployment_json_path),
                "output_blueprint_path": str(output_blueprint_path),
                "error":                 None,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    # ══════════════════════════════════════════════════════════════════════
    # Public: deploy_contract_script
    # ══════════════════════════════════════════════════════════════════════

    def deploy_contract_script(
        self,
        blueprint_path: str,
        script_address_str: str,
        output_json_path: Optional[str] = None,
        base_deployment: Optional[dict] = None,
    ) -> dict:
        """
        Post the compiled script as a reference script UTXO at the script address.

        Args:
            blueprint_path:     Path to the parameterized blueprint JSON.
            script_address_str: Bech32 script address string.
            output_json_path:   Where to write the ref deployment JSON.
                                Defaults to deployment_ref_<timestamp>.json.
            base_deployment:    Existing deployment dict to extend.
                                If None, only the reference_script fields are written.

        Returns:
            Result dict with success, tx_hash, reference_script coords,
            output_json_path, error.
        """
        if output_json_path is None:
            output_json_path = f"deployment_ref_{_timestamp_str()}.json"

        try:
            blueprint    = json.loads(Path(blueprint_path).read_text())
            script, _    = _script_from_blueprint(blueprint)
            script_address = Address.from_primitive(script_address_str)

            print(f"  Script address:  {script_address}")
            print(f"  Blueprint:       {blueprint_path}")

            ref_output = TransactionOutput(
                address=script_address,
                amount=REF_SCRIPT_UTXO_LOVELACE,
                script=script,
                post_alonzo=True,
            )

            builder = TransactionBuilder(
                self._context,
                ttl=self._context.last_block_slot + TTL_BUFFER_SLOTS,
            )
            builder.add_input_address(self._funding_address)
            builder.add_output(ref_output)

            print("  Building and signing reference script transaction...")
            signed_tx = builder.build_and_sign(
                signing_keys=[self._funding_key],
                change_address=self._funding_address,
            )
            tx_hash = str(signed_tx.id)

            print(f"  Submitting reference script tx: {tx_hash}")
            self._context.submit_tx(signed_tx)

            confirmed, err = _confirm(
                self._context, self._funding_address, script_address, tx_hash
            )
            if not confirmed:
                return {
                    "success": False,
                    "error": f"Reference script tx submitted but confirmation failed: {err}",
                    "tx_hash": tx_hash,
                }

            print("  Reference script confirmed.")

            # ── Write output JSON ─────────────────────────────────────────
            if base_deployment:
                output_record = dict(base_deployment)
            else:
                output_record = {}

            output_record["deployment_type"] = "reference"
            output_record["reference_script"] = {
                "tx_hash":      tx_hash,
                "output_index": 0,
            }

            Path(output_json_path).write_text(json.dumps(output_record, indent=2))
            print(f"  Reference deployment JSON written: {output_json_path}")

            return {
                "success":          True,
                "tx_hash":          tx_hash,
                "reference_script": {"tx_hash": tx_hash, "output_index": 0},
                "output_json_path": str(output_json_path),
                "error":            None,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    # ══════════════════════════════════════════════════════════════════════
    # Public: deploy_contract
    # ══════════════════════════════════════════════════════════════════════

    def deploy_contract(
        self,
        genesis_utxo_ref: Optional[str] = None,
        output_blueprint_path: str = "bootstrap_generated_plutus.json",
        deployment_json_path: str = "deployment.json",
    ) -> dict:
        """
        Full deployment pipeline: genesis + reference script.

        Runs deploy_genesis() then deploy_contract_script() in sequence.
        Produces deployment.json and deployment_ref_<timestamp>.json.

        Returns a combined result dict.
        """
        print("\n=== Step 1: Genesis ===")
        genesis_result = self.deploy_genesis(
            genesis_utxo_ref=genesis_utxo_ref,
            output_blueprint_path=output_blueprint_path,
            deployment_json_path=deployment_json_path,
        )

        if not genesis_result["success"]:
            return {
                "success": False,
                "step":    "genesis",
                "error":   genesis_result["error"],
                "genesis": genesis_result,
                "reference_script": None,
            }

        print("\n=== Step 2: Reference Script ===")
        base_deployment = json.loads(Path(deployment_json_path).read_text())
        ref_result = self.deploy_contract_script(
            blueprint_path=genesis_result["output_blueprint_path"],
            script_address_str=genesis_result["script_address"],
            base_deployment=base_deployment,
        )

        if not ref_result["success"]:
            return {
                "success": False,
                "step":    "reference_script",
                "error":   ref_result["error"],
                "genesis": genesis_result,
                "reference_script": ref_result,
            }

        return {
            "success":          True,
            "policy_id":        genesis_result["policy_id"],
            "script_address":   genesis_result["script_address"],
            "genesis_tx":       genesis_result["tx_hash"],
            "ref_script_tx":    ref_result["tx_hash"],
            "deployment_json":  genesis_result["deployment_json_path"],
            "ref_json":         ref_result["output_json_path"],
            "error":            None,
            "genesis":          genesis_result,
            "reference_script": ref_result,
        }


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="CardanoDeployer",
        description="ZPEPG Cardano contract deployment utility.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--network", choices=["preprod", "mainnet"], default="preprod",
                        help="Target network (default: preprod).")
    parser.add_argument("--funding-key", required=True, metavar="CBOR_HEX",
                        help="CborHex of the funding payment signing key.")
    parser.add_argument("--perm-keys", default="perm_keys.json", metavar="PATH",
                        help="Path to perm_keys.json (default: perm_keys.json).")
    parser.add_argument("--source-blueprint", metavar="PATH",
                        help="Path to unparameterized plutus.json from aiken build.")
    parser.add_argument("--output-blueprint", default="bootstrap_generated_plutus.json", metavar="PATH",
                        help="Output path for parameterized blueprint (default: bootstrap_generated_plutus.json).")
    parser.add_argument("--deployment-json", default="deployment.json", metavar="PATH",
                        help="Output path for deployment.json (default: deployment.json).")
    parser.add_argument("--genesis-ref", metavar="TXHASH#INDEX",
                        help="Genesis UTXO reference. If omitted, interactive UTXO picker runs.")
    parser.add_argument("--genesis-only", action="store_true",
                        help="Run genesis transaction only. Skip reference script deployment.")
    parser.add_argument("--update-contract-reference", action="store_true",
                        help="Post a new reference script UTXO for an existing deployment. "
                             "Reads --deployment-json, produces updated_deployment_<timestamp>.json.")
    parser.add_argument("--list-utxos", action="store_true",
                        help="List UTxOs at the funding address and exit.")
    return parser


def _pick_utxo_interactive(utxos: list[dict]) -> Optional[dict]:
    if not utxos:
        print("No UTxOs found at funding address.")
        return None

    print("\nUTxOs at funding address:")
    for i, u in enumerate(utxos):
        tokens = " + tokens" if u["has_tokens"] else ""
        print(f"  [{i}] {u['ref']}  {u['ada']:.6f} ADA{tokens}")

    while True:
        raw = input(f"\nSelect genesis UTXO index [0-{len(utxos)-1}]: ").strip()
        try:
            idx = int(raw)
            if 0 <= idx < len(utxos):
                selected = utxos[idx]
                confirm = input(f"Use {selected['ref']} ({selected['ada']} ADA)? [y/N]: ").strip().lower()
                if confirm == "y":
                    return selected
                print("Cancelled, try again.")
            else:
                print(f"Index out of range.")
        except ValueError:
            print("Enter a number.")


def main(argv=None) -> int:
    parser = _build_parser()
    args   = parser.parse_args(argv)

    deployer = CardanoDeployer(
        network=args.network,
        funding_signing_key_cbor=args.funding_key,
        perm_keys_path=args.perm_keys,
        source_blueprint_path=args.source_blueprint,
    )

    # ── MODE: list UTxOs ────────────────────────────────────────────────
    if args.list_utxos:
        print(f"\nUTxOs at {deployer._funding_address} ({args.network}):")
        utxos = deployer.list_utxos()
        if not utxos:
            print("  (none)")
        for u in utxos:
            tokens = " + tokens" if u["has_tokens"] else ""
            print(f"  {u['ref']}  {u['ada']:.6f} ADA{tokens}")
        return 0

    # ── MODE: update contract reference ─────────────────────────────────
    if args.update_contract_reference:
        deployment_path = args.deployment_json
        if not Path(deployment_path).exists():
            print(f"Error: {deployment_path} not found. Pass --deployment-json.", file=sys.stderr)
            return 1

        base = json.loads(Path(deployment_path).read_text())
        blueprint_path   = base["contract"]["bootstrap_generated_plutus_path"]
        script_address   = base["contract"]["script_address"]
        output_json_path = f"updated_deployment_{_timestamp_str()}.json"

        print(f"\n=== Update Contract Reference ===")
        print(f"  Existing deployment: {deployment_path}")
        print(f"  Blueprint:           {blueprint_path}")
        print(f"  Script address:      {script_address}")
        print(f"  Output:              {output_json_path}")

        confirm = input("\nProceed? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            return 0

        result = deployer.deploy_contract_script(
            blueprint_path=blueprint_path,
            script_address_str=script_address,
            output_json_path=output_json_path,
            base_deployment=base,
        )

        if result["success"]:
            print(f"\n=== Update Complete ===")
            print(f"  tx_hash:    {result['tx_hash']}")
            print(f"  output:     {result['output_json_path']}")
        else:
            print(f"\nError: {result['error']}", file=sys.stderr)
            return 1
        return 0

    # ── MODES: full or genesis-only ──────────────────────────────────────
    if not args.source_blueprint:
        print("Error: --source-blueprint required for deployment.", file=sys.stderr)
        return 1

    # Resolve genesis ref
    genesis_ref = args.genesis_ref
    if not genesis_ref:
        utxos = deployer.list_utxos()
        selected = _pick_utxo_interactive(utxos)
        if not selected:
            print("No UTXO selected. Aborted.", file=sys.stderr)
            return 1
        genesis_ref = selected["ref"]

    print(f"\n=== ZPEPG Cardano Deployment ({args.network}) ===")
    print(f"  Funding address:  {deployer._funding_address}")
    print(f"  Genesis UTXO:     {genesis_ref}")
    print(f"  Source blueprint: {args.source_blueprint}")
    print(f"  Mode:             {'genesis only' if args.genesis_only else 'full (genesis + reference script)'}")

    confirm = input("\nProceed? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return 0

    if args.genesis_only:
        result = deployer.deploy_genesis(
            genesis_utxo_ref=genesis_ref,
            output_blueprint_path=args.output_blueprint,
            deployment_json_path=args.deployment_json,
        )
        if result["success"]:
            print(f"\n=== Genesis Complete ===")
            print(f"  tx_hash:         {result['tx_hash']}")
            print(f"  policy_id:       {result['policy_id']}")
            print(f"  script_address:  {result['script_address']}")
            print(f"  deployment.json: {result['deployment_json_path']}")
        else:
            print(f"\nError: {result['error']}", file=sys.stderr)
            return 1
    else:
        result = deployer.deploy_contract(
            genesis_utxo_ref=genesis_ref,
            output_blueprint_path=args.output_blueprint,
            deployment_json_path=args.deployment_json,
        )
        if result["success"]:
            print(f"\n=== Full Deployment Complete ===")
            print(f"  policy_id:       {result['policy_id']}")
            print(f"  script_address:  {result['script_address']}")
            print(f"  genesis_tx:      {result['genesis_tx']}")
            print(f"  ref_script_tx:   {result['ref_script_tx']}")
            print(f"  deployment.json: {result['deployment_json']}")
            print(f"  ref_json:        {result['ref_json']}")
        else:
            print(f"\nError (step={result.get('step')}): {result['error']}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())