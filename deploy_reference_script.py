"""
deploy_reference_script.py - Deploy the compiled registry contract as a
reference script UTXO on-chain, then write an extended deployment JSON.

This is a one-off script, not a CLI. Fill in the config block, review it,
then run. It reads an existing deployment.json (genesis already done),
posts the compiled script to a UTXO at the script address, waits for
confirmation, and writes a new deployment_ref.json with the reference
script UTXO coordinates added.

Why the script address?
  A UTXO at the script address with no valid MasterDatum can never be
  spent - the spend validator will reject it immediately. This makes the
  reference script UTXO a permanent, immutable on-chain artifact.

Output deployment_ref.json shape:
  All fields from the original deployment.json, plus:
    "deployment_type": "reference"
    "reference_script": {
      "tx_hash": "...",
      "output_index": 0
    }
"""

import json
import time
from pathlib import Path

from pycardano import (
    Address, BlockFrostChainContext, Network, PaymentSigningKey,
    PlutusV3Script, ScriptHash, TransactionBuilder, TransactionOutput,
)
from blockfrost import ApiUrls, ApiError

# ════════════════════════════════════════════════════════════════════════
# CONFIG - review carefully before running
# ════════════════════════════════════════════════════════════════════════

DEPLOYMENT_JSON_PATH        = "/workspaces/ZPEPGAikenDevEnvironment/testnet_deployment.json"
DEPLOYMENT_REF_JSON_PATH    = "/workspaces/ZPEPGAikenDevEnvironment/testnet_deployment_ref.json"
FUNDING_SIGNING_KEY_CBOR    = "58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e"
BLOCKFROST_PROJECT_ID       = "preprodviqzO4lW7gcYXeQoxtAg50qneXkq00dW"

# Confirmation timeouts (seconds)
CONFIRMATION_TIMEOUT_S      = 300.0
CONFIRMATION_POLL_INTERVAL_S = 5.0
ADDRESS_CATCHUP_TIMEOUT_S   = 30.0
ADDRESS_CATCHUP_POLL_S      = 2.0

# Minimum lovelace for the reference script UTXO.
# The ledger requires at least 2 ADA for a UTXO carrying a large script.
# 10 ADA gives comfortable headroom regardless of script size.
REF_SCRIPT_UTXO_LOVELACE    = 33_000_000

TTL_BUFFER_SLOTS            = 200

# ════════════════════════════════════════════════════════════════════════


def _confirm(api, context, funding_address, tx_hash: str) -> tuple[bool, str | None]:
    """
    Three-stage confirmation identical to basic_client_v4._confirm():
      Stage 1 - transaction-level confirmation
      Stage 2 - script address UTXO reflects the new tx
      Stage 3 - funding address change output appears
    """
    deadline = time.monotonic() + CONFIRMATION_TIMEOUT_S
    last_err = None

    # Stage 1
    print("  [confirm] Stage 1: waiting for transaction confirmation...")
    while time.monotonic() < deadline:
        try:
            result = api.transaction_utxos(hash=tx_hash)
            if getattr(result, "outputs", None):
                print(f"  [confirm] Stage 1: confirmed.")
                break
        except ApiError as e:
            last_err = str(e)
        time.sleep(CONFIRMATION_POLL_INTERVAL_S)
    else:
        return False, f"Stage 1 timeout after {CONFIRMATION_TIMEOUT_S}s. Last error: {last_err}"

    # Stage 2 - wait for the reference script UTXO to appear at script address
    print("  [confirm] Stage 2: waiting for script address UTXO to appear...")
    addr_deadline = time.monotonic() + ADDRESS_CATCHUP_TIMEOUT_S
    while time.monotonic() < addr_deadline:
        try:
            utxos = context.utxos(context._script_address)
            if any(str(u.input.transaction_id) == tx_hash for u in utxos):
                print("  [confirm] Stage 2: script address caught up.")
                break
        except Exception as e:
            last_err = str(e)
        time.sleep(ADDRESS_CATCHUP_POLL_S)
    else:
        return False, (
            f"Stage 2 timeout: script address did not reflect tx {tx_hash} "
            f"within {ADDRESS_CATCHUP_TIMEOUT_S}s. Last error: {last_err}"
        )

    # Stage 3 - wait for funding address change output
    print("  [confirm] Stage 3: waiting for funding address change output...")
    fund_deadline = time.monotonic() + ADDRESS_CATCHUP_TIMEOUT_S
    while time.monotonic() < fund_deadline:
        try:
            utxos = context.utxos(context._funding_address)
            if any(str(u.input.transaction_id) == tx_hash for u in utxos):
                print("  [confirm] Stage 3: funding address caught up.")
                return True, None
        except Exception as e:
            last_err = str(e)
        time.sleep(ADDRESS_CATCHUP_POLL_S)

    return False, (
        f"Stage 3 timeout: funding address did not reflect change output "
        f"within {ADDRESS_CATCHUP_TIMEOUT_S}s. Last error: {last_err}"
    )


def main():
    print("=== ZPEPG Reference Script Deployment ===\n")

    # ── Load existing deployment ─────────────────────────────────────────
    deployment = json.loads(Path(DEPLOYMENT_JSON_PATH).read_text())
    policy_id_hex = deployment["contract"]["policy_id"]
    script_address_str = deployment["contract"]["script_address"]
    blueprint_path = deployment["contract"]["bootstrap_generated_plutus_path"]

    print(f"Existing deployment:  {DEPLOYMENT_JSON_PATH}")
    print(f"Policy ID:            {policy_id_hex}")
    print(f"Script address:       {script_address_str}")
    print(f"Blueprint:            {blueprint_path}")
    print(f"Output will be:       {DEPLOYMENT_REF_JSON_PATH}\n")

    if Path(DEPLOYMENT_REF_JSON_PATH).exists():
        print(f"WARNING: {DEPLOYMENT_REF_JSON_PATH} already exists and will be overwritten.")

    confirm = input("Type 'deploy' to confirm and proceed: ").strip()
    if confirm != "deploy":
        print("Aborted. Nothing was submitted.")
        return 1

    # ── Load script ──────────────────────────────────────────────────────
    blueprint = json.loads(Path(blueprint_path).read_text())
    spend_validator = next(
        v for v in blueprint["validators"] if v["title"].endswith(".spend")
    )
    script = PlutusV3Script(bytes.fromhex(spend_validator["compiledCode"]))
    print(f"\nLoaded script ({len(bytes.fromhex(spend_validator['compiledCode']))} bytes).")

    # ── Set up Blockfrost context ────────────────────────────────────────
    context = BlockFrostChainContext(
        project_id=BLOCKFROST_PROJECT_ID,
        network=Network.TESTNET,
        base_url=ApiUrls.preprod.value,
    )

    # ── Load funding key and addresses ──────────────────────────────────
    funding_key = PaymentSigningKey.from_cbor(FUNDING_SIGNING_KEY_CBOR)
    funding_address = Address(
        payment_part=funding_key.to_verification_key().hash(),
        network=Network.TESTNET,
    )
    script_address = Address.from_primitive(script_address_str)

    # Attach addresses to context so _confirm() can access them
    context._script_address = script_address
    context._funding_address = funding_address

    print(f"Funding address:      {funding_address}")
    print(f"Script address:       {script_address}")

    # ── Build transaction ────────────────────────────────────────────────
    print("\nBuilding reference script transaction...")

    ref_script_output = TransactionOutput(
        address=script_address,
        amount=REF_SCRIPT_UTXO_LOVELACE,
        script=script,
        post_alonzo=True,
    )

    builder = TransactionBuilder(
        context,
        ttl=context.last_block_slot + TTL_BUFFER_SLOTS,
    )
    builder.add_input_address(funding_address)
    builder.add_output(ref_script_output)

    signed_tx = builder.build_and_sign(
        signing_keys=[funding_key],
        change_address=funding_address,
    )
    tx_hash = str(signed_tx.id)
    print(f"Transaction built. Hash: {tx_hash}")

    # ── Submit ───────────────────────────────────────────────────────────
    print("Submitting...")
    context.submit_tx(signed_tx)
    print("Submitted.")

    # ── Confirm ──────────────────────────────────────────────────────────
    print("\nWaiting for confirmation...")
    confirmed, err = _confirm(context.api, context, funding_address, tx_hash)

    if not confirmed:
        print(f"\nERROR: Confirmation failed: {err}")
        print(f"Transaction {tx_hash} may still confirm later.")
        print(f"If it does, manually add to {DEPLOYMENT_REF_JSON_PATH}:")
        print(f'  "reference_script": {{"tx_hash": "{tx_hash}", "output_index": 0}}')
        return 1

    # ── Write deployment_ref.json ────────────────────────────────────────
    ref_deployment = dict(deployment)
    ref_deployment["deployment_type"] = "reference"
    ref_deployment["reference_script"] = {
        "tx_hash": tx_hash,
        "output_index": 0,
    }

    Path(DEPLOYMENT_REF_JSON_PATH).write_text(json.dumps(ref_deployment, indent=2))

    print(f"\n=== Reference script deployment complete ===")
    print(f"  tx_hash:         {tx_hash}")
    print(f"  output_index:    0")
    print(f"  script address:  {script_address}")
    print(f"  written to:      {DEPLOYMENT_REF_JSON_PATH}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())