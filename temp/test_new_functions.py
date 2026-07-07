"""
test_new_functions.py - Test withdraw, rotate_key, link_forward, link_backward
on the new CardanoClient.

Run each test in order. Each one is commented out by default — uncomment
the one you want to test, run it, verify, then move to the next.
"""

import json
from CardanoClient import CardanoClient

DEPLOYMENT   = "testnet_deployment_ref.json"
PERM_KEYS    = "perm_keys.json"
FUNDING_KEY  = "58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e"

client = CardanoClient(DEPLOYMENT, PERM_KEYS, FUNDING_KEY)

def print_state():
    state = client.get_master_state()
    print("\n--- Current State ---")
    for k, v in state.items():
        print(f"  {k}: {v}")
    print()

def print_result(label, result):
    print(f"\n[{label}]")
    print(f"  success:  {result.success}")
    print(f"  tx_hash:  {result.tx_hash}")
    if result.error:
        print(f"  error:    {result.error}")


# ════════════════════════════════════════════════════════════════════════
# TEST 1: rotate_key (operator)
# Rotates the operator key to the same key it already is — a no-op
# in terms of state change, but proves the full rotate path works.
# ════════════════════════════════════════════════════════════════════════

def test_rotate_operator():
    print_state()
    perm_keys = json.loads(__import__("pathlib").Path(PERM_KEYS).read_text())
    current_operator_vk = perm_keys["operator"]["public_key_hex"]
    print(f"Rotating operator key to same value: {current_operator_vk}")
    result = client.rotate_key(key_type="operator", new_public_key_hex=current_operator_vk)
    print_result("rotate_key(operator)", result)
    if result.success:
        print_state()


# ════════════════════════════════════════════════════════════════════════
# TEST 2: withdraw
# Withdraws a small amount of lovelace to the owner address.
# Make sure the script address has enough ADA above the master UTXO min.
# ════════════════════════════════════════════════════════════════════════
def test_withdraw():
    # ── Snapshot before ──────────────────────────────────────────────
    from pycardano import Address, Network, VerificationKeyHash

    print_state()

    utxos_before = client._backend.utxos(client._funding_address)
    total_before = sum(u.output.amount.coin for u in utxos_before)
    print(f"\n--- Funding address UTxOs BEFORE ---")
    for u in utxos_before:
        print(f"  {u.input.transaction_id}#{u.input.index}  {u.output.amount.coin} lovelace")
    print(f"  TOTAL: {total_before} lovelace ({total_before/1_000_000:.6f} ADA)")

    # ── Withdraw ─────────────────────────────────────────────────────
    amount = 2_000_000
    print(f"\nWithdrawing {amount} lovelace...")
    result = client.withdraw(amount_lovelace=amount)
    print_result("withdraw(2 ADA)", result)

    if result.success:
        # ── Snapshot after ───────────────────────────────────────────
        utxos_after = client._backend.utxos(client._funding_address)
        total_after = sum(u.output.amount.coin for u in utxos_after)
        print(f"\n--- Funding address UTxOs AFTER ---")
        for u in utxos_after:
            print(f"  {u.input.transaction_id}#{u.input.index}  {u.output.amount.coin} lovelace")
        print(f"  TOTAL: {total_after} lovelace ({total_after/1_000_000:.6f} ADA)")
        print(f"\n  Difference: {total_before - total_after} lovelace (fee + any sent out)")

        # ── Owner address UTxOs after ─────────────────────────────────
        _, datum = client._get_master_utxo()
        pay_cred = datum.owner_address.payment_credential
        owner_addr = Address(
            payment_part=VerificationKeyHash(pay_cred.credential_hash),
            network=Network.TESTNET,
        )
        print(f"\n--- Owner address UTxOs AFTER ({owner_addr}) ---")
        owner_utxos = client._backend.utxos(owner_addr)
        total_owner = sum(u.output.amount.coin for u in owner_utxos)
        for u in owner_utxos:
            print(f"  {u.input.transaction_id}#{u.input.index}  {u.output.amount.coin} lovelace")
        print(f"  TOTAL: {total_owner} lovelace ({total_owner/1_000_000:.6f} ADA)")

        print_state()

# ════════════════════════════════════════════════════════════════════════
# TEST 3: link_backward
# Links this deployment backward to a dummy predecessor.
# Uses fake addresses/policy IDs since this is testnet.
# WARNING: this is permanent and can only be written once.
# ════════════════════════════════════════════════════════════════════════

def test_link_backward():
    print_state()
    print("Writing backward link (PERMANENT - only run this once)...")
    result = client.link_backward(
        prev_script_address="addr_test1wpvln3yfa87mqygpcnzgyrvdpm2xtmsg0ry83kqet6ny9tgdasnc7",
        prev_policy_id="59f9c489e9fdb01101c4c4820d8d0ed465ee0878c878d8195ea642ad",
        link_reason="test-backward-link",
        linked_at=1000000000,
        instructions="This is a test backward link on preprod.",
    )
    print_result("link_backward()", result)
    if result.success:
        print_state()


# ════════════════════════════════════════════════════════════════════════
# TEST 4: link_forward
# Links this deployment forward to a dummy successor.
# WARNING: this is permanent and can only be written once.
# ════════════════════════════════════════════════════════════════════════

def test_link_forward():
    print_state()
    print("Writing forward link (PERMANENT - only run this once)...")
    result = client.link_forward(
        next_script_address="addr_test1wpvln3yfa87mqygpcnzgyrvdpm2xtmsg0ry83kqet6ny9tgdasnc7",
        next_policy_id="59f9c489e9fdb01101c4c4820d8d0ed465ee0878c878d8195ea642ad",
        link_reason="test-forward-link",
        linked_at=1000000001,
        instructions="This is a test forward link on preprod.",
    )
    print_result("link_forward()", result)
    if result.success:
        print_state()


# ════════════════════════════════════════════════════════════════════════
# Run — uncomment one at a time
# ════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    test_rotate_operator()
    test_withdraw()
    test_link_backward()
    test_link_forward()