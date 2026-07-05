"""
measure_lag.py - Standalone measurement script.

Snapshots the master UTXO and funding-address UTXO set BEFORE and
immediately AFTER a confirmed Resume call, then polls the funding
address repeatedly until its UTXO set actually changes from the
"immediately after" snapshot - timing exactly how long that takes.

This isolates ONE specific question: once a write is confirmed, how
long does Blockfrost's funding-address index take to reflect the
change that write caused (its own fee/collateral consumption)?
"""

import time
from basic_client import BareClient

DEPLOYMENT_JSON_PATH = "testnet_deployment.json"
PERM_KEYS_JSON_PATH = "perm_keys.json"
FUNDING_SIGNING_KEY = "58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e"

POLL_INTERVAL_S = 2.0
POLL_TIMEOUT_S = 180.0


def snapshot_funding(client):
    utxos = client.context.utxos(client.funding_address)
    return {(str(u.input.transaction_id), u.input.index): u.output.amount.coin for u in utxos}


def print_snapshot(label, snap):
    print(f"{label} ({len(snap)} UTXOs):")
    for (tx_id, idx), coin in snap.items():
        print(f"  {tx_id}#{idx}  {coin/1e6:.4f} ADA")


def main():
    client = BareClient(DEPLOYMENT_JSON_PATH, PERM_KEYS_JSON_PATH, FUNDING_SIGNING_KEY)

    print("=== BEFORE RESUME ===")
    master_utxo_before, master_datum_before = client._get_master_utxo()
    print(f"Master UTXO: {master_utxo_before.input.transaction_id}#{master_utxo_before.input.index}")
    print(f"nonce={master_datum_before.nonce} is_paused={master_datum_before.is_paused}")

    funding_before = snapshot_funding(client)
    print_snapshot("Funding UTXOs BEFORE", funding_before)

    print("\n=== CALLING RESUME ===")
    ok, tx_hash, err = client.resume()
    print(f"success={ok} tx={tx_hash}")
    if err:
        print(f"error={err}")
        return

    print("\n=== IMMEDIATELY AFTER RESUME CONFIRMED ===")
    master_utxo_after, master_datum_after = client._get_master_utxo()
    print(f"Master UTXO: {master_utxo_after.input.transaction_id}#{master_utxo_after.input.index}")
    print(f"nonce={master_datum_after.nonce} is_paused={master_datum_after.is_paused}")

    funding_immediately_after = snapshot_funding(client)
    print_snapshot("Funding UTXOs IMMEDIATELY AFTER", funding_immediately_after)

    changed_from_before = funding_immediately_after != funding_before
    print(f"\nFunding set already different from BEFORE snapshot? {changed_from_before}")

    print(f"\n=== POLLING funding address every {POLL_INTERVAL_S}s until it changes again ===")
    start = time.monotonic()
    poll_count = 0
    while True:
        poll_count += 1
        elapsed = time.monotonic() - start
        current = snapshot_funding(client)
        if current != funding_immediately_after:
            print(f"\nCHANGED after {elapsed:.1f}s ({poll_count} polls)")
            print_snapshot("New funding UTXO set", current)
            break
        if elapsed > POLL_TIMEOUT_S:
            print(f"\nTIMEOUT: funding UTXO set never changed within {POLL_TIMEOUT_S}s ({poll_count} polls)")
            break
        time.sleep(POLL_INTERVAL_S)


if __name__ == "__main__":
    main()