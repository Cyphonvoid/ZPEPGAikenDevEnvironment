"""
sweep_test_v2.py - Full function sweep test for CardanoClient v2.

Tests every public method in order:
  1.  get_master_state()
  2.  pause_minting()
  3.  resume_minting()
  4.  double pause — second should fail
  5.  resume after double pause
  6.  create_document_token()
  7.  create_document_token() — invalid sha256
  8.  create_document_token() — while paused
  9.  update_key() — rotate operator to same value
  10. update_key() — invalid key length
  11. link_backward() — fresh, should succeed
  12. link_backward() — already set, contract rejects
  13. link_forward() — fresh, should succeed
  14. link_forward() — already set, contract rejects
  15. withdraw_extra_funds() — send ADA to script then recover it
  16. get_token_global_id()
  17. get_all_tokens()
  18. Final get_master_state()
"""

import json
import time
from pathlib import Path
from CardanoClient import CardanoClient
from pycardano import (
    BlockFrostChainContext, Network, Address, PaymentSigningKey,
    TransactionBuilder, TransactionOutput,
)
from blockfrost import ApiUrls

DEPLOYMENT  = "deployment_ref_2026-07-06_10-01-25.json"  # update to your v2 ref json
PERM_KEYS   = "perm_keys.json"
FUNDING_KEY = "58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e"
FUNDING_ADDR = "addr_test1vq2aeqdjc9m40zas6k6sa00nvqd4m9sh67c3ujjxx2vn4lg5a4mvw"

client = CardanoClient(DEPLOYMENT, PERM_KEYS, FUNDING_KEY, network="preprod")

# Raw context for sending plain ADA to script address in test 15
_context = BlockFrostChainContext(
    project_id="preprodviqzO4lW7gcYXeQoxtAg50qneXkq00dW",
    network=Network.TESTNET,
    base_url=ApiUrls.preprod.value,
)
_funding_key = PaymentSigningKey.from_cbor(FUNDING_KEY)
_funding_address = Address.from_primitive(FUNDING_ADDR)

results = []



import os

def generate_uuid7() -> str:
    """Generate a UUIDv7 string (time-ordered, RFC 9562)."""
    unix_ts_ms = int(time.time() * 1000)
    ts_bytes   = unix_ts_ms.to_bytes(6, byteorder="big")
    rand_bytes = bytearray(os.urandom(10))
    rand_bytes[0] = (rand_bytes[0] & 0x0F) | 0x70   # version 7
    rand_bytes[2] = (rand_bytes[2] & 0x3F) | 0x80   # variant bits
    raw = ts_bytes + bytes(rand_bytes)
    h = raw.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def print_receipt(receipt: dict):
    display = {k: v for k, v in receipt.items() if k != "receipt_json"}
    print(json.dumps(display, indent=2))
    if receipt.get("receipt_json"):
        print(f"  [receipt_json present: {len(receipt['receipt_json'])} chars]")


def check(label: str, receipt: dict, expect_success: bool, checks: dict = None):
    passed = True
    failures = []

    if receipt["success"] != expect_success:
        passed = False
        failures.append(
            f"Expected success={expect_success}, got success={receipt['success']}"
        )

    if expect_success:
        for required in ["tx_hash", "fee_lovelace", "nonce_used", "nonce_after",
                         "submitted_at", "confirmed_at", "duration_s", "receipt_json"]:
            if receipt.get(required) is None:
                passed = False
                failures.append(f"Missing required field: {required}")
    else:
        for required in ["error", "error_type"]:
            if not receipt.get(required):
                passed = False
                failures.append(f"Missing required failure field: {required}")

    if checks:
        for field, expected in checks.items():
            actual = receipt.get(field)
            if actual != expected:
                passed = False
                failures.append(f"Field {field!r}: expected {expected!r}, got {actual!r}")

    status = "PASS" if passed else "FAIL"
    results.append((label, passed))
    print(f"\n  [{status}] {label}")
    for f in failures:
        print(f"    x {f}")
    return passed


# ════════════════════════════════════════════════════════════════════════
# 1. get_master_state
# ════════════════════════════════════════════════════════════════════════

section("1. get_master_state()")
state = client.get_master_state()
print(json.dumps(state, indent=2))

state_ok = all(k in state for k in [
    "utxo", "nonce", "is_paused", "total_token_count",
    "policy_id", "authority_key", "operator_key", "owner_key",
    "forward_link", "backward_link",
])
results.append(("get_master_state", state_ok))
print(f"\n  [{'PASS' if state_ok else 'FAIL'}] get_master_state — all expected fields present")

initial_nonce = state["nonce"]
perm_keys = json.loads(Path(PERM_KEYS).read_text())
current_operator_vk = perm_keys["operator"]["public_key_hex"]

# ════════════════════════════════════════════════════════════════════════
# 2. pause_minting
# ════════════════════════════════════════════════════════════════════════

section("2. pause_minting()")
r = client.pause_minting()
print_receipt(r)
check("pause_minting — success", r, expect_success=True)

# ════════════════════════════════════════════════════════════════════════
# 3. resume_minting
# ════════════════════════════════════════════════════════════════════════

section("3. resume_minting()")
r = client.resume_minting()
print_receipt(r)
check("resume_minting — success", r, expect_success=True)

# ════════════════════════════════════════════════════════════════════════
# 4. double pause — second should fail
# ════════════════════════════════════════════════════════════════════════

section("4. pause_minting() then pause_minting() again — second should fail")
r1 = client.pause_minting()
print_receipt(r1)
check("double-pause first — success", r1, expect_success=True)

r2 = client.pause_minting()
print_receipt(r2)
check("double-pause second — contract rejects", r2, expect_success=False)

# ════════════════════════════════════════════════════════════════════════
# 5. resume after double pause
# ════════════════════════════════════════════════════════════════════════

section("5. resume_minting() to restore state")
r = client.resume_minting()
print_receipt(r)
check("resume after double-pause — success", r, expect_success=True)

# ════════════════════════════════════════════════════════════════════════
# 6. create_document_token
# ════════════════════════════════════════════════════════════════════════

section("6. create_document_token()")
mint1_uuid = generate_uuid7()
r = client.create_document_token(
    cross_chain_global_id=mint1_uuid,
    sha256_hash="ab" * 32,
    upload_date="2026-07-05T00:00:00Z",
    version=1,
    token_data={"test": "sweep_v2", "cycle": 1},
    is_unique_document=True,
)
print_receipt(r)
check("create_document_token — success", r, expect_success=True)

# ════════════════════════════════════════════════════════════════════════
# 7. create_document_token with invalid sha256
# ════════════════════════════════════════════════════════════════════════

section("7. create_document_token() with invalid sha256 — invalid_input")
r = client.create_document_token(
    cross_chain_global_id="sweep-test-bad-hash",
    sha256_hash="abcd",
    upload_date="2026-07-05T00:00:00Z",
    version=1,
    token_data={},
)
print_receipt(r)
check("create_document_token invalid sha256 — invalid_input", r, expect_success=False,
      checks={"error_type": "invalid_input"})

# ════════════════════════════════════════════════════════════════════════
# 8. create_document_token while paused
# ════════════════════════════════════════════════════════════════════════
section("8. create_document_token() while paused — contract rejects")
client.pause_minting()
r = client.create_document_token(
    cross_chain_global_id="sweep-test-paused-mint-1",
    sha256_hash="cd" * 32,
    upload_date="2026-07-05T00:00:00Z",
    version=1,
    token_data={},
)
print_receipt(r)
check("create_document_token while paused — script_rejected", r, expect_success=False)
client.resume_minting()

# ════════════════════════════════════════════════════════════════════════
# 9. update_key (rotate operator to same value)
# ════════════════════════════════════════════════════════════════════════

section("9. update_key() — rotate operator to same value")
r = client.update_key(key_type="operator", new_public_key_hex=current_operator_vk)
print_receipt(r)
check("update_key operator — success", r, expect_success=True)

# ════════════════════════════════════════════════════════════════════════
# 10. update_key with invalid key length
# ════════════════════════════════════════════════════════════════════════

section("10. update_key() with invalid key — invalid_input")
r = client.update_key(key_type="operator", new_public_key_hex="abcd")
print_receipt(r)
check("update_key bad key — invalid_input", r, expect_success=False,
      checks={"error_type": "invalid_input"})

# ════════════════════════════════════════════════════════════════════════
# 11. link_backward — fresh, should succeed
# ════════════════════════════════════════════════════════════════════════

section("11. link_backward() — fresh contract, should succeed")
r = client.link_backward(
    prev_script_address="addr_test1wpvln3yfa87mqygpcnzgyrvdpm2xtmsg0ry83kqet6ny9tgdasnc7",
    prev_policy_id="59f9c489e9fdb01101c4c4820d8d0ed465ee0878c878d8195ea642ad",
    link_reason="sweep-test-v2-backward",
    linked_at=1000000000,
    instructions="Sweep v2 test backward link.",
)
print_receipt(r)
check("link_backward fresh — success", r, expect_success=True)

# ════════════════════════════════════════════════════════════════════════
# 12. link_backward again — already set, contract rejects
# ════════════════════════════════════════════════════════════════════════

section("12. link_backward() again — already set, contract rejects")
r = client.link_backward(
    prev_script_address="addr_test1wpvln3yfa87mqygpcnzgyrvdpm2xtmsg0ry83kqet6ny9tgdasnc7",
    prev_policy_id="59f9c489e9fdb01101c4c4820d8d0ed465ee0878c878d8195ea642ad",
    link_reason="sweep-test-v2-backward-2",
    linked_at=1000000002,
    instructions="Should fail.",
)
print_receipt(r)
check("link_backward already set — contract rejects", r, expect_success=False)

# ════════════════════════════════════════════════════════════════════════
# 13. link_forward — fresh, should succeed
# ════════════════════════════════════════════════════════════════════════

section("13. link_forward() — fresh contract, should succeed")
r = client.link_forward(
    next_script_address="addr_test1wpvln3yfa87mqygpcnzgyrvdpm2xtmsg0ry83kqet6ny9tgdasnc7",
    next_policy_id="59f9c489e9fdb01101c4c4820d8d0ed465ee0878c878d8195ea642ad",
    link_reason="sweep-test-v2-forward",
    linked_at=1000000001,
    instructions="Sweep v2 test forward link.",
)
print_receipt(r)
check("link_forward fresh — success", r, expect_success=True)

# ════════════════════════════════════════════════════════════════════════
# 14. link_forward again — already set, contract rejects
# ════════════════════════════════════════════════════════════════════════

section("14. link_forward() again — already set, contract rejects")
r = client.link_forward(
    next_script_address="addr_test1wpvln3yfa87mqygpcnzgyrvdpm2xtmsg0ry83kqet6ny9tgdasnc7",
    next_policy_id="59f9c489e9fdb01101c4c4820d8d0ed465ee0878c878d8195ea642ad",
    link_reason="sweep-test-v2-forward-2",
    linked_at=1000000003,
    instructions="Should fail.",
)
print_receipt(r)
check("link_forward already set — contract rejects", r, expect_success=False)

# ════════════════════════════════════════════════════════════════════════
# 15. withdraw_extra_funds — send 10 ADA to script then recover it
# ════════════════════════════════════════════════════════════════════════

section("15. withdraw_extra_funds() — send 10 ADA to script then recover")

# Snapshot before
utxos_before = client._backend.utxos(_funding_address)
total_before = sum(u.output.amount.coin for u in utxos_before)
print(f"  Funding wallet before send: {total_before / 1_000_000:.6f} ADA")

# Send 10 ADA to script address
print("  Sending 10 ADA to script address...")
builder = TransactionBuilder(_context)
builder.add_input_address(_funding_address)
builder.add_output(TransactionOutput(address=client._script_address, amount=10_000_000))
signed_tx = builder.build_and_sign(signing_keys=[_funding_key], change_address=_funding_address)
send_tx_hash = str(signed_tx.id)
_context.submit_tx(signed_tx)
print(f"  Submitted: {send_tx_hash}")

# Wait for tx to confirm and Blockfrost to index script address
print("  Waiting for confirmation and Blockfrost indexing...")
for _ in range(60):
    try:
        result = _context.api.transaction_utxos(hash=send_tx_hash)
        if getattr(result, "outputs", None):
            break
    except Exception:
        pass
    time.sleep(5)


# Wait for Blockfrost to index the new UTxO at script address
print("  Waiting for script address to reflect new UTxO...")
deadline = time.monotonic() + 60
while time.monotonic() < deadline:
    utxos = client._backend.utxos(client._script_address)
    if any(str(u.input.transaction_id) == send_tx_hash for u in utxos):
        print("  Script address caught up.")
        print("  Confirmed.")
        break
    time.sleep(3)
else:
    print("  Warning: script address did not reflect new UTxO within 60s, proceeding anyway.")

# Snapshot after send
utxos_after_send = client._backend.utxos(_funding_address)
total_after_send = sum(u.output.amount.coin for u in utxos_after_send)
print(f"  Funding wallet after send:  {total_after_send / 1_000_000:.6f} ADA")
print(f"  Sent ~10 ADA + fee, net change: {(total_after_send - total_before) / 1_000_000:.6f} ADA")

# Now recover it
print("\n  Recovering 10 ADA via withdraw_extra_funds()...")
r = client.withdraw_extra_funds(
    to_address=FUNDING_ADDR,
    amount_lovelace=10_000_000,
)
print_receipt(r)

if r["success"]:
    utxos_after_recover = client._backend.utxos(_funding_address)
    total_after_recover = sum(u.output.amount.coin for u in utxos_after_recover)
    net = total_after_recover - total_before
    print(f"\n  Funding wallet after recovery: {total_after_recover / 1_000_000:.6f} ADA")
    print(f"  Net change from before:        {net / 1_000_000:.6f} ADA")
    print(f"  (expected ~-0.6 ADA from two transaction fees)")
    wallet_received = net > -2_000_000  # net loss should be less than 2 ADA (just fees)
    check("withdraw_extra_funds — success", r, expect_success=True)
    results.append(("withdraw_extra_funds net loss < 2 ADA (fees only)", wallet_received))
    print(f"\n  [{'PASS' if wallet_received else 'FAIL'}] Net loss {net / 1_000_000:.6f} ADA (fees only, 10 ADA recovered)")
else:
    check("withdraw_extra_funds — success", r, expect_success=True)

# ════════════════════════════════════════════════════════════════════════
# 16. get_token_global_id
# ════════════════════════════════════════════════════════════════════════

section("16. get_tokens_by_global_id()")
token = client.get_tokens_by_global_id(mint1_uuid)[0]
print(json.dumps(token, indent=2) if token else "None")
token_found = (
    token is not None
    and token.get("cross_chain_global_id") == mint1_uuid.replace("-", "")
)
results.append(("get_tokens_by_global_id", token_found))
print(f"\n  [{'PASS' if token_found else 'FAIL'}] get_tokens_by_global_id — token found with correct global ID")

# ════════════════════════════════════════════════════════════════════════
# 17. get_all_tokens
# ════════════════════════════════════════════════════════════════════════

section("17. get_all_tokens()")
tokens = client.get_all_tokens()
print(f"  Total tokens found: {len(tokens)}")
for t in tokens:
    print(f"    {t['cross_chain_global_id']} — {t['utxo']}")
tokens_ok = len(tokens) >= 1
results.append(("get_all_tokens", tokens_ok))
print(f"\n  [{'PASS' if tokens_ok else 'FAIL'}] get_all_tokens — at least 1 token found")


# ════════════════════════════════════════════════════════════════════════
# 18. get_token_by_version()
# ════════════════════════════════════════════════════════════════════════

section("19. get_token_by_version()")

version_test_uuid = generate_uuid7()

r1 = client.create_document_token(
    cross_chain_global_id=version_test_uuid,
    sha256_hash="11" * 32,
    upload_date="2026-07-06T00:00:00Z",
    version=1,
    token_data={"test": "version_lookup", "v": 1},
    is_unique_document=True,
)
print_receipt(r1)
check("create_document_token v1 for version lookup — success", r1, expect_success=True)

r2 = client.create_document_token(
    cross_chain_global_id=version_test_uuid,
    sha256_hash="22" * 32,
    upload_date="2026-07-06T00:00:00Z",
    version=2,
    token_data={"test": "version_lookup", "v": 2},
    is_unique_document=False,
)
print_receipt(r2)
check("create_document_token v2 for version lookup — success", r2, expect_success=True)

token_v1 = client.get_token_by_version(version_test_uuid, 1)
token_v2 = client.get_token_by_version(version_test_uuid, 2)

print("\n  Token v1:")
print(json.dumps(token_v1, indent=2) if token_v1 else "None")
print("\n  Token v2:")
print(json.dumps(token_v2, indent=2) if token_v2 else "None")

version_lookup_ok = (
    token_v1 is not None and token_v1.get("version") == 1
    and token_v2 is not None and token_v2.get("version") == 2
)
results.append(("get_token_by_version", version_lookup_ok))
print(f"\n  [{'PASS' if version_lookup_ok else 'FAIL'}] get_token_by_version — v1 and v2 both found with correct versions")

# ════════════════════════════════════════════════════════════════════════
# 19. Final state check
# ════════════════════════════════════════════════════════════════════════

section("19. Final get_master_state()")
final_state = client.get_master_state()
print(json.dumps(final_state, indent=2))
nonce_advanced = final_state["nonce"] > initial_nonce
results.append(("nonce advanced from initial", nonce_advanced))
print(f"\n  [{'PASS' if nonce_advanced else 'FAIL'}] Nonce advanced: {initial_nonce} -> {final_state['nonce']}")

# ════════════════════════════════════════════════════════════════════════
# Summary
# ════════════════════════════════════════════════════════════════════════

section("SUMMARY")
passed = sum(1 for _, ok in results if ok)
total  = len(results)
print(f"\nPassed: {passed}/{total}\n")
for label, ok in results:
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {label}")