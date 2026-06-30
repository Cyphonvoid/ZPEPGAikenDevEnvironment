"""
smoke_test_deploy_contract.py - DEVNET-ONLY smoke test for the
restructured genesis flow: CardanoNetworkClient.deploy_contract(), which
internally calls initiate_contract_genesis() (pure class-level, no
instance involved) and then returns a ready client afterward.

This replaces smoke_test_mint_beacon.py, which tested the now-retired
mint_beacon() instance method + bootstrap_genesis() classmethod. Same
purpose: prove the new code path actually works on cheap, fast,
consequence-free devnet before trusting it against real testnet via
deploy.py.
"""

import json
from pathlib import Path

from CardanoNetworkClient import CardanoNetworkClient, CardanoNet

# ── Config ──────────────────────────────────────────────────────────────

FUNDING_SIGNING_KEY = "test test test test test test test test test test test test test test test test test test test test test test test sauce"
PERM_KEYS_JSON_PATH = "perm_keys.json"
SOURCE_BLUEPRINT_PATH = "/workspaces/ZPEPGAikenDevEnvironment/zpepg_aiken_registry/plutus.json"
OUTPUT_BLUEPRINT_PATH = "smoke_test2_bootstrap_generated_plutus.json"
DEPLOYMENT_JSON_OUTPUT_PATH = "smoke_test2_deployment.json"

BEACON_ASSET_NAME = b"ZPEPG-BEACON-SMOKETEST2"  # distinct from the prior smoke test's deployment too
ASSET_NAME_PREFIX = b"ZPEPG-ARCHIVE-DOC"

NETWORK_TYPE = CardanoNet.DEVNET


def main():
    print("=== deploy_contract() smoke test (devnet only, restructured genesis) ===\n")

    perm_keys = json.loads(Path(PERM_KEYS_JSON_PATH).read_text())
    operator_key = bytes.fromhex(perm_keys["operator"]["private_key_hex"])
    authority_key = bytes.fromhex(perm_keys["authority"]["private_key_hex"])
    owner_key = bytes.fromhex(perm_keys["owner"]["private_key_hex"])
    print("Loaded perm_keys.json.")

    print("\n--- Calling CardanoNetworkClient.deploy_contract() ---")
    print("(No instance exists yet - this is a pure classmethod call.)")
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

    print(f"\n  tx_hash:         {genesis.tx_result.tx_hash}")
    print(f"  confirmed:       {genesis.tx_result.confirmed}")
    print(f"  policy_id:       {genesis.policy_id_hex}")
    print(f"  script_address:  {genesis.script_address}")
    print(f"  deployment.json: {genesis.deployment_json_path}")

    print("\n--- Confirming the returned client actually works (get_master_state) ---")
    state = client.get_master_state()
    print(f"  nonce:     {state.datum.nonce}")
    print(f"  is_paused: {state.datum.is_paused}")
    if state.datum.nonce != 0:
        print("\nFAIL: expected nonce=0 immediately after genesis.")
        return 1

    print("\n--- Confirming a FRESH client, pointed at the same deployment.json, is equivalent ---")
    print("(This is the 'discard the returned client, construct a new one later' check.)")
    fresh_client = CardanoNetworkClient(
        deployment=DEPLOYMENT_JSON_OUTPUT_PATH,
        funding_signing_key=FUNDING_SIGNING_KEY,
        operator_key=operator_key,
        authority_key=authority_key,
        owner_key=owner_key,
        network_type=NETWORK_TYPE,
    )
    fresh_state = fresh_client.get_master_state()
    if fresh_state.datum.nonce != state.datum.nonce:
        print(f"FAIL: fresh client sees nonce={fresh_state.datum.nonce}, expected {state.datum.nonce}")
        return 1
    print(f"  Confirmed equivalent: nonce={fresh_state.datum.nonce}")

    print("\ndeploy_contract() smoke test PASSED - restructured genesis flow confirmed working.")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())