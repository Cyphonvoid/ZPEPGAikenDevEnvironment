"""
sweep_test.py - Full function sweep test for CardanoClient.

Tests every public method in order:
  1. get_master_state()   - read state, no tx
  2. pause()              - freeze registry
  3. resume()             - unfreeze registry
  4. mint()               - mint a document token
  5. withdraw()           - withdraw lovelace to owner
  6. rotate_key()         - rotate operator key (to same value, reversible)
  7. link_forward()       - will fail (already set), validates contract rejection
  8. link_backward()      - will fail (already set), validates contract rejection

For each operation, prints the full receipt dict and whether it matched
the expected outcome. A summary at the end shows pass/fail per test.
"""

import json
import time
from CardanoClient import CardanoClient

DEPLOYMENT  = "deployment_ref_2026-07-05_11-01-02.json"
PERM_KEYS   = "perm_keys.json"
FUNDING_KEY = "58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e"

client = CardanoClient(DEPLOYMENT, PERM_KEYS, FUNDING_KEY, network="preprod")

results = []


def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def print_receipt(receipt: dict):
    # Print without receipt_json to keep terminal clean
    display = {k: v for k, v in receipt.items() if k != "receipt_json"}
    print(json.dumps(display, indent=2))
    if receipt.get("receipt_json"):
        print(f"  [receipt_json present: {len(receipt['receipt_json'])} chars]")


def check(label: str, receipt: dict, expect_success: bool, checks: dict = None):
    """
    Validate a receipt against expectations.
    checks: optional dict of {field: expected_value} to assert on the receipt.
    """
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
        if receipt.get("nonce_after") and receipt.get("nonce_used"):
            if receipt["nonce_after"] != receipt["nonce_used"] + 1:
                passed = False
                failures.append(
                    f"nonce_after {receipt['nonce_after']} != nonce_used {receipt['nonce_used']} + 1"
                )
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
        print(f"    ✗ {f}")
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
perm_keys = json.loads(__import__("pathlib").Path(PERM_KEYS).read_text())
current_operator_vk = perm_keys["operator"]["public_key_hex"]

# ════════════════════════════════════════════════════════════════════════
# 2. pause
# ════════════════════════════════════════════════════════════════════════

section("2. pause()")
r = client.pause_minting()
print_receipt(r)
check("pause — success", r, expect_success=True, checks={"operation": "pause"})

# ════════════════════════════════════════════════════════════════════════
# 3. resume
# ════════════════════════════════════════════════════════════════════════

section("3. resume()")
r = client.resume_minting()
print_receipt(r)
check("resume — success", r, expect_success=True, checks={"operation": "resume"})

# ════════════════════════════════════════════════════════════════════════
# 4. pause again then try to pause again (should fail at contract)
# ════════════════════════════════════════════════════════════════════════

section("4. pause() then pause() again — second should fail")
r1 = client.pause_minting()
print_receipt(r1)
check("double-pause first — success", r1, expect_success=True)

r2 = client.pause_minting()
print_receipt(r2)
check("double-pause second — contract rejects", r2, expect_success=False,
      checks={"operation": "pause"})

# Resume so we can continue
section("4b. resume() to restore state")
r = client.resume_minting()
print_receipt(r)
check("resume after double-pause — success", r, expect_success=True)

# ════════════════════════════════════════════════════════════════════════
# 5. mint
# ════════════════════════════════════════════════════════════════════════

section("5. mint()")
r = client.create_document_token(
    cross_chain_global_id="sweep-test-mint-001",
    sha256_hash="ab" * 32,
    upload_date="2026-07-05T00:00:00Z",
    version=1,
    token_data={"test": "sweep", "cycle": 1},
    is_unique_document=True,
)
print_receipt(r)
check("mint — success", r, expect_success=True, checks={
    "operation": "mint",
    "cross_chain_global_id": "sweep-test-mint-001",
    "version": 1,
    "is_unique_document": True,
})

# ════════════════════════════════════════════════════════════════════════
# 6. mint with invalid sha256 (should fail client-side)
# ════════════════════════════════════════════════════════════════════════

section("6. mint() with invalid sha256_hash — should fail with invalid_input")
r = client.create_document_token(
    cross_chain_global_id="sweep-test-bad-hash",
    sha256_hash="abcd",  # too short
    upload_date="2026-07-05T00:00:00Z",
    version=1,
    token_data={},
)
print_receipt(r)
check("mint invalid sha256 — invalid_input", r, expect_success=False,
      checks={"operation": "mint", "error_type": "invalid_input"})

# ════════════════════════════════════════════════════════════════════════
# 7. mint while paused (should fail at contract)
# ════════════════════════════════════════════════════════════════════════

section("7. mint() while paused — contract rejects")
client.pause_minting()
r = client.create_document_token(
    cross_chain_global_id="sweep-test-paused-mint",
    sha256_hash="cd" * 32,
    upload_date="2026-07-05T00:00:00Z",
    version=1,
    token_data={},
)
print_receipt(r)
check("mint while paused — script_rejected", r, expect_success=False,
      checks={"operation": "mint", "error_type": "script_rejected"})
client.resume_minting()

# ════════════════════════════════════════════════════════════════════════
# 8. withdraw
# ════════════════════════════════════════════════════════════════════════

section("8. withdraw()")
r = client.withdraw(amount_lovelace=2_000_000)
print_receipt(r)
check("withdraw 2 ADA — success", r, expect_success=True, checks={
    "operation": "withdraw",
    "amount_lovelace": 2_000_000,
})

# ════════════════════════════════════════════════════════════════════════
# 9. withdraw invalid amount
# ════════════════════════════════════════════════════════════════════════

section("9. withdraw() with invalid amount — should fail with invalid_input")
r = client.withdraw(amount_lovelace=0)
print_receipt(r)
check("withdraw 0 — invalid_input", r, expect_success=False,
      checks={"operation": "withdraw", "error_type": "invalid_input"})

# ════════════════════════════════════════════════════════════════════════
# 10. rotate_key (operator, same value — reversible no-op)
# ════════════════════════════════════════════════════════════════════════

section("10. rotate_key() — rotate operator to same value")
r = client.update_key(key_type="operator", new_public_key_hex=current_operator_vk)
print_receipt(r)
check("update_key operator — success", r, expect_success=True, checks={
    "operation": "update_key",
    "key_type": "operator",
    "new_key_hex": current_operator_vk,
})

# ════════════════════════════════════════════════════════════════════════
# 11. rotate_key invalid key length
# ════════════════════════════════════════════════════════════════════════

section("11. rotate_key() with invalid key — should fail with invalid_input")
r = client.update_key(key_type="operator", new_public_key_hex="abcd")
print_receipt(r)
check("update_key bad key — invalid_input", r, expect_success=False,
      checks={"operation": "update_key", "error_type": "invalid_input"})



# ════════════════════════════════════════════════════════════════════════
# 12. link_backward — fresh contract, should succeed
# ════════════════════════════════════════════════════════════════════════

section("12. link_backward() — fresh contract, should succeed")
r = client.link_backward(
    prev_script_address="addr_test1wpvln3yfa87mqygpcnzgyrvdpm2xtmsg0ry83kqet6ny9tgdasnc7",
    prev_policy_id="59f9c489e9fdb01101c4c4820d8d0ed465ee0878c878d8195ea642ad",
    link_reason="sweep-test-backward",
    linked_at=1000000000,
    instructions="Sweep test backward link.",
)
print_receipt(r)
check("link_backward fresh — success", r, expect_success=True,
      checks={"operation": "link_backward"})

# ════════════════════════════════════════════════════════════════════════
# 13. link_backward again — slot now set, contract should reject
# ════════════════════════════════════════════════════════════════════════

section("13. link_backward() again — already set, contract rejects")
r = client.link_backward(
    prev_script_address="addr_test1wpvln3yfa87mqygpcnzgyrvdpm2xtmsg0ry83kqet6ny9tgdasnc7",
    prev_policy_id="59f9c489e9fdb01101c4c4820d8d0ed465ee0878c878d8195ea642ad",
    link_reason="sweep-test-backward-2",
    linked_at=1000000002,
    instructions="Should fail.",
)
print_receipt(r)
check("link_backward already set — contract rejects", r, expect_success=False,
      checks={"operation": "link_backward"})

# ════════════════════════════════════════════════════════════════════════
# 14. link_forward — fresh slot, should succeed
# ════════════════════════════════════════════════════════════════════════

section("14. link_forward() — fresh contract, should succeed")
r = client.link_forward(
    next_script_address="addr_test1wpvln3yfa87mqygpcnzgyrvdpm2xtmsg0ry83kqet6ny9tgdasnc7",
    next_policy_id="59f9c489e9fdb01101c4c4820d8d0ed465ee0878c878d8195ea642ad",
    link_reason="sweep-test-forward",
    linked_at=1000000001,
    instructions="Sweep test forward link.",
)
print_receipt(r)
check("link_forward fresh — success", r, expect_success=True,
      checks={"operation": "link_forward"})

# ════════════════════════════════════════════════════════════════════════
# 15. link_forward again — slot now set, contract should reject
# ════════════════════════════════════════════════════════════════════════

section("15. link_forward() again — already set, contract rejects")
r = client.link_forward(
    next_script_address="addr_test1wpvln3yfa87mqygpcnzgyrvdpm2xtmsg0ry83kqet6ny9tgdasnc7",
    next_policy_id="59f9c489e9fdb01101c4c4820d8d0ed465ee0878c878d8195ea642ad",
    link_reason="sweep-test-forward-2",
    linked_at=1000000003,
    instructions="Should fail.",
)
print_receipt(r)
check("link_forward already set — contract rejects", r, expect_success=False,
      checks={"operation": "link_forward"})

# ════════════════════════════════════════════════════════════════════════
# 16. Final state check
# ════════════════════════════════════════════════════════════════════════

section("16. Final get_master_state()")
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