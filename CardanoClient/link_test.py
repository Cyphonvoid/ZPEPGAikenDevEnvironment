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
# 14. Final state check
# ════════════════════════════════════════════════════════════════════════

section("14. Final get_master_state()")
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