"""
regenerate_testnet_blueprint.py - Deterministically regenerates the
testnet_bootstrap_generated_plutus.json that was overwritten after the
real testnet deployment.

Parameterization is deterministic: same source blueprint + same
genesis_ref + same beacon_asset_name ALWAYS produces the same compiled
bytecode and the same policy ID. Running this should reproduce exactly
c267b074b476cd65bf61950e3274f7919a200e5ca6a156b0ba8713d7.
"""

import json
from CardanoDeployer.cardano_types import OutputReference
from CardanoDeployer.cardano_workflow import AikenBlueprint

# ── These must exactly match what deploy.py used ───────────────────────

# The genesis UTXO that was consumed during the real testnet deployment
# (from testnet_deployment.json's genesis_transaction_hash + output_index 0)
GENESIS_TX_HASH = "2a386f523e4f38a83b165cc1fbe6571fa3c226abc6ccdf8c5468f5b8594c6ff7"
GENESIS_OUTPUT_INDEX = 0

BEACON_ASSET_NAME = b"ZPEPG-BEACON"

SOURCE_BLUEPRINT_PATH = "/workspaces/ZPEPGAikenDevEnvironment/zpepg_aiken_registry/plutus.json"
OUTPUT_BLUEPRINT_PATH = "testnet_bootstrap_generated_plutus.json"

EXPECTED_POLICY_ID = "c267b074b476cd65bf61950e3274f7919a200e5ca6a156b0ba8713d7"

# ── Regenerate ─────────────────────────────────────────────────────────

genesis_ref = OutputReference(
    transaction_id=bytes.fromhex(GENESIS_TX_HASH),
    output_index=GENESIS_OUTPUT_INDEX,
)

print(f"Regenerating blueprint from genesis_ref {GENESIS_TX_HASH}#{GENESIS_OUTPUT_INDEX}...")
applied = AikenBlueprint.apply_parameters(
    genesis_ref=genesis_ref,
    beacon_asset_name=BEACON_ASSET_NAME,
    source_blueprint_path=SOURCE_BLUEPRINT_PATH,
    output_blueprint_path=OUTPUT_BLUEPRINT_PATH,
)

print(f"Generated policy_id: {applied.policy_id_hex}")
print(f"Expected policy_id:  {EXPECTED_POLICY_ID}")

if applied.policy_id_hex == EXPECTED_POLICY_ID:
    print("\nMATCH - blueprint correctly regenerated.")
    print(f"Written to: {OUTPUT_BLUEPRINT_PATH}")
else:
    print("\nMISMATCH - something differs from the original deployment inputs.")
    print("Check GENESIS_TX_HASH / GENESIS_OUTPUT_INDEX / BEACON_ASSET_NAME above.")