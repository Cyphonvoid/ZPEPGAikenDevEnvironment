"""
test_withdraw_extra_funds.py - Send 50 ADA to script address then recover it
via WithdrawExtraFunds. Shows funding wallet UTxOs before and after.
"""

import json
from CardanoClient import CardanoClient
from pycardano import (
    BlockFrostChainContext, Network, Address, PaymentSigningKey,
    TransactionBuilder, TransactionOutput
)
from blockfrost import ApiUrls

DEPLOYMENT   = "deployment_ref_2026-07-06_04-40-22.json"  # update to your v2 ref json
PERM_KEYS    = "perm_keys.json"
FUNDING_KEY  = "58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e"
FUNDING_ADDR = "addr_test1vq2aeqdjc9m40zas6k6sa00nvqd4m9sh67c3ujjxx2vn4lg5a4mvw"

SEND_AMOUNT    = 10_000_000   # 50 ADA to script address
RECOVER_AMOUNT = 10_000_000   # recover it all back

client = CardanoClient(DEPLOYMENT, PERM_KEYS, FUNDING_KEY, network="preprod")

# ── Shared Blockfrost context for sending plain ADA ──────────────────────
context = BlockFrostChainContext(
    project_id="preprodviqzO4lW7gcYXeQoxtAg50qneXkq00dW",
    network=Network.TESTNET,
    base_url=ApiUrls.preprod.value,
)
funding_key = PaymentSigningKey.from_cbor(FUNDING_KEY)
funding_address = Address.from_primitive(FUNDING_ADDR)
script_address = client._script_address


def show_funding_utxos(label: str):
    print(f"\n--- Funding Wallet UTxOs {label} ---")
    utxos = context.utxos(funding_address)
    total = 0
    for u in utxos:
        tokens = " + tokens" if u.output.amount.multi_asset else ""
        print(f"  {u.input.transaction_id}#{u.input.index}  "
              f"{u.output.amount.coin / 1_000_000:.6f} ADA{tokens}")
        total += u.output.amount.coin
    print(f"  TOTAL: {total / 1_000_000:.6f} ADA")
    return total


def show_script_utxos(label: str):
    print(f"\n--- Script Address UTxOs {label} ---")
    utxos = context.utxos(script_address)
    total = 0
    plain_utxos = []
    for u in utxos:
        has_tokens = bool(u.output.amount.multi_asset)
        tokens = " + tokens" if has_tokens else " (plain ADA - non-citizen)"
        print(f"  {u.input.transaction_id}#{u.input.index}  "
              f"{u.output.amount.coin / 1_000_000:.6f} ADA{tokens}")
        total += u.output.amount.coin
        if not has_tokens:
            plain_utxos.append(u)
    print(f"  TOTAL: {total / 1_000_000:.6f} ADA")
    print(f"  Plain (non-citizen) UTxOs: {len(plain_utxos)}")
    return plain_utxos


# ════════════════════════════════════════════════════════════════════════
# STEP 1: Show initial state
# ════════════════════════════════════════════════════════════════════════

print("=" * 60)
print("STEP 1: Initial State")
print("=" * 60)
total_before = show_funding_utxos("BEFORE")
show_script_utxos("BEFORE")


# ════════════════════════════════════════════════════════════════════════
# STEP 2: Send 50 ADA to script address
# ════════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 60}")
print(f"STEP 2: Sending {SEND_AMOUNT / 1_000_000:.0f} ADA to script address")
print("=" * 60)

builder = TransactionBuilder(context)
builder.add_input_address(funding_address)
builder.add_output(TransactionOutput(
    address=script_address,
    amount=SEND_AMOUNT,
))
signed_tx = builder.build_and_sign(
    signing_keys=[funding_key],
    change_address=funding_address,
)
send_tx_hash = str(signed_tx.id)
context.submit_tx(signed_tx)
print(f"Submitted: {send_tx_hash}")

# Wait for confirmation
import time
print("Waiting for confirmation...")
for _ in range(60):
    try:
        result = context.api.transaction_utxos(hash=send_tx_hash)
        if getattr(result, "outputs", None):
            print("Confirmed.")
            break
    except Exception:
        pass
    time.sleep(5)
    
print("Waiting for Blockfrost to index new UTxO...")
time.sleep(15)  # give Blockfrost time to index the new script UTxO

show_funding_utxos("AFTER SEND")
show_script_utxos("AFTER SEND (should have new plain ADA UTXO)")


# ════════════════════════════════════════════════════════════════════════
# STEP 3: Recover the 50 ADA via WithdrawExtraFunds
# ════════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 60}")
print(f"STEP 3: Recovering {RECOVER_AMOUNT / 1_000_000:.0f} ADA via withdraw_extra_funds")
print("=" * 60)

result = client.withdraw_extra_funds(
    to_address=FUNDING_ADDR,
    amount_lovelace=RECOVER_AMOUNT,
)

display = {k: v for k, v in result.items() if k != "receipt_json"}
print(json.dumps(display, indent=2))


# ════════════════════════════════════════════════════════════════════════
# STEP 4: Show final state
# ════════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 60}")
print("STEP 4: Final State")
print("=" * 60)
total_after = show_funding_utxos("AFTER RECOVERY")
show_script_utxos("AFTER RECOVERY")

print(f"\n{'=' * 60}")
print("SUMMARY")
print("=" * 60)
print(f"  Funding wallet before:  {total_before / 1_000_000:.6f} ADA")
print(f"  Funding wallet after:   {total_after / 1_000_000:.6f} ADA")
print(f"  Net change:             {(total_after - total_before) / 1_000_000:.6f} ADA")
print(f"  (expected ~-{(SEND_AMOUNT + RECOVER_AMOUNT) / 2 / 1_000_000:.0f} ADA net from fees)")