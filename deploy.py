"""
deploy.py - Standalone genesis deployment script, separate from the
existing CLI deployer (cardano_deploy.py, which remains devnet-only via
GenesisTransaction). This one targets TESTNET or MAINNET via
CardanoNetworkClient.bootstrap_genesis(), which means it automatically
gets Blockfrost support for free - no separate Blockfrost-specific
deployment logic needed anywhere.

USAGE: fill in the config block below, then run directly. No CLI args/
modes (unlike cardano_deploy.py) - this is meant for deliberate,
one-shot, carefully-reviewed real-network deployments, not casual re-runs.
"""

import json
from pathlib import Path

from CardanoNetworkClient_v5 import CardanoNetworkClient, CardanoNet

# ════════════════════════════════════════════════════════════════════════
# CONFIG - review every value carefully before running against a real network
# ════════════════════════════════════════════════════════════════════════

NETWORK_TYPE = CardanoNet.TESTNET   # CardanoNet.TESTNET (preprod) or CardanoNet.MAINNET

FUNDING_SIGNING_KEY = "58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e"
PERM_KEYS_JSON_PATH = "perm_keys.json"

SOURCE_BLUEPRINT_PATH = "/workspaces/ZPEPGAikenDevEnvironment/zpepg_aiken_registry/plutus.json"
OUTPUT_BLUEPRINT_PATH = "testnet_bootstrap_generated_plutus.json"
DEPLOYMENT_JSON_OUTPUT_PATH = "testnet_deployment.json"

BEACON_ASSET_NAME = b"ZPEPG-BEACON"          # no "-TEST" suffix for a real network deployment
ASSET_NAME_PREFIX = b"ZPEPG-ARCHIVE-DOC"


def main():
    print(f"=== ZPEPG Genesis Deployment - {NETWORK_TYPE.value.upper()} ===\n")
    print("Review the config block at the top of this script carefully before continuing.")
    confirm = input(f"Type the network name ('{NETWORK_TYPE.value}') to confirm and proceed: ").strip()
    if confirm != NETWORK_TYPE.value:
        print("Confirmation did not match - aborting. Nothing was deployed.")
        return 1

    perm_keys = json.loads(Path(PERM_KEYS_JSON_PATH).read_text())
    operator_key  = bytes.fromhex(perm_keys["operator"]["public_key_hex"])
    authority_key = bytes.fromhex(perm_keys["authority"]["public_key_hex"])
    owner_key     = bytes.fromhex(perm_keys["owner"]["public_key_hex"])
    print("Loaded perm_keys.json.")

    print(f"\nCompiling + parameterizing archive_registry, then submitting genesis transaction to {NETWORK_TYPE.value}...")
    print("(This costs real fees on testnet/mainnet and is irreversible once confirmed.)\n")

    client, genesis = CardanoNetworkClient.deploy_contract(
        funding_signing_key=FUNDING_SIGNING_KEY,
        operator_key=operator_key,
        authority_key=authority_key,
        owner_key=owner_key,
        network_type=NETWORK_TYPE,
        beacon_asset_name=BEACON_ASSET_NAME,
        asset_name_prefix=ASSET_NAME_PREFIX,
        source_blueprint_path=SOURCE_BLUEPRINT_PATH,
        output_blueprint_path=OUTPUT_BLUEPRINT_PATH,
        deployment_json_output_path=DEPLOYMENT_JSON_OUTPUT_PATH,
    )

    print(f"\nSUCCESS")
    print(f"  tx_hash:        {genesis.tx_result.tx_hash}")
    print(f"  confirmed:      {genesis.tx_result.confirmed}")
    print(f"  script address: {genesis.script_address}")
    print(f"  policy ID:      {genesis.policy_id_hex}")
    print(f"  deployment.json written to: {genesis.deployment_json_path}")

    print("\nVerifying via get_master_state()...")
    state = client.get_master_state()
    print(f"  nonce:     {state.datum.nonce}")
    print(f"  is_paused: {state.datum.is_paused}")

    print(f"\n=== {NETWORK_TYPE.value.upper()} deployment complete ===")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())