"""
quick_client_write_test.py - Exercises CardanoNetworkClient's write
methods directly: resume() (since the contract is currently paused from
the earlier test), then mint_document() as a bigger end-to-end check.

Costs real (devnet) lovelace in fees - safe to run repeatedly on devnet.
"""

import json
from CardanoNetworkClient import CardanoNetworkClient, CardanoNet

DEPLOYMENT_JSON_PATH = "deployment.json"
FUNDING_SIGNING_KEY = "test test test test test test test test test test test test test test test test test test test test test test test sauce"

perm_keys = json.loads(open("perm_keys.json").read())
operator_key = bytes.fromhex(perm_keys["operator"]["private_key_hex"])
authority_key = bytes.fromhex(perm_keys["authority"]["private_key_hex"])
owner_key = bytes.fromhex(perm_keys["owner"]["private_key_hex"])

client = CardanoNetworkClient(
    deployment=DEPLOYMENT_JSON_PATH,
    funding_signing_key=FUNDING_SIGNING_KEY,
    operator_key=operator_key,
    authority_key=authority_key,
    owner_key=owner_key,
    network_type=CardanoNet.DEVNET,
)

from CardanoDeployer.cardano_types import AikenTrue

state = client.get_master_state()
print(f"Current state: nonce={state.datum.nonce}, is_paused={state.datum.is_paused}")

if isinstance(state.datum.is_paused, AikenTrue):
    print("\n--- Calling resume() ---")
    result = client.resume()
    print(f"  tx_hash:   {result.tx_hash}")
    print(f"  confirmed: {result.confirmed}")
    print(f"  new nonce: {result.new_master_state.datum.nonce}")
    print(f"  new is_paused: {result.new_master_state.datum.is_paused}")
else:
    print("\nAlready resumed - skipping resume() call.")

print("\n--- Calling mint_document() ---")
import hashlib
test_cross_chain_id = b"network-client-write-test-0001"
test_sha256 = hashlib.sha256(b"test content").digest()
test_upload_date = b"2026-06-30T00:00:00Z"
test_token_data = b'{"title": "Network client write test"}'

current_state = client.get_master_state()
mint_result = client.mint_document(
    cross_chain_global_id=test_cross_chain_id,
    sha256_hash=test_sha256,
    upload_date=test_upload_date,
    version=1,
    token_data=test_token_data,
    is_unique_document=True,
    valid_lower_bound=current_state.datum.nonce,
)
print(f"  tx_hash:   {mint_result.tx_hash}")
print(f"  confirmed: {mint_result.confirmed}")
print(f"  new nonce: {mint_result.new_master_state.datum.nonce}")
print(f"  new total_token_count: {mint_result.new_master_state.datum.stats.total_token_count}")

print("\n--- Verifying via list_all_documents() ---")
docs = client.list_all_documents()
print(f"  Found {len(docs)} document(s) total")
for d in docs:
    print(f"    - {d.cardano_asset_id.hex()}  cross_chain_id={d.cross_chain_global_id!r}")

print("\nWrite test complete.")