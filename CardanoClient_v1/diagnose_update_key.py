"""
diagnose_update_key.py - Diagnose update_key failure.
"""
import json
from CardanoClient import CardanoClient
from pathlib import Path

DEPLOYMENT  = "deployment_ref_2026-07-06_05-41-54.json"  # update to your current ref json
PERM_KEYS   = "perm_keys.json"
FUNDING_KEY = "58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e"

client = CardanoClient(DEPLOYMENT, PERM_KEYS, FUNDING_KEY, network="preprod")

perm_keys = json.loads(Path(PERM_KEYS).read_text())
current_operator_vk = perm_keys["operator"]["public_key_hex"]

print(f"Current state:")
state = client.get_master_state()
print(f"  nonce: {state['nonce']}")
print(f"  on-chain operator_key: {state['operator_key']}")
print(f"  perm_keys operator vk: {current_operator_vk}")
print(f"  match: {state['operator_key'] == current_operator_vk}")

print(f"\nAttempting update_key(operator) to same value...")
r = client.update_key(key_type="operator", new_public_key_hex=current_operator_vk)
display = {k: v for k, v in r.items() if k != "receipt_json"}
print(json.dumps(display, indent=2))