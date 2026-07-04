"""
measure_mint_only.py - Isolated mint-only repeated test.

No pause/resume mixed in at all. Just mint(), called N times in a row,
zero gaps, full instrumentation - to isolate whether mint specifically
behaves differently from pause/resume under the same basic_client_v3
three-stage confirmation.
"""

import time
from basic_client_v3 import BareClient

DEPLOYMENT_JSON_PATH = "testnet_deployment.json"
PERM_KEYS_JSON_PATH = "perm_keys.json"
FUNDING_SIGNING_KEY = "58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e"

N_CYCLES = 1


def snapshot_funding(client):
    utxos = client.context.utxos(client.funding_address)
    return {(str(u.input.transaction_id), u.input.index): u.output.amount.coin for u in utxos}


def run_one_mint(client, cycle_num):
    print(f"\n{'='*60}")
    print(f"MINT CYCLE {cycle_num}/{N_CYCLES}")
    print(f"{'='*60}")

    master_utxo_before, master_datum_before = client._get_master_utxo()
    print(f"BEFORE: master={master_utxo_before.input.transaction_id}#{master_utxo_before.input.index} "
          f"nonce={master_datum_before.nonce} token_count={master_datum_before.stats.total_token_count}")

    cross_chain_global_id = f"mint-only-test-cycle-{cycle_num}".encode()
    sha256_hash = bytes([cycle_num % 256]) * 32
    upload_date = b"2026-07-03T00:00:00Z"
    token_data = f'{{"cycle": {cycle_num}}}'.encode()

    start_call = time.monotonic()
    ok, tx_hash, err = client.mint(
        cross_chain_global_id=cross_chain_global_id,
        sha256_hash=sha256_hash,
        upload_date=upload_date,
        version=1,
        token_data=token_data,
    )
    call_duration = time.monotonic() - start_call

    print(f"success={ok} tx={tx_hash} call_duration={call_duration:.1f}s")
    if err:
        print(f"FULL ERROR: {err}")
        return {"cycle": cycle_num, "success": False, "error": err, "call_duration": call_duration}

    master_utxo_after, master_datum_after = client._get_master_utxo()
    print(f"AFTER:  master={master_utxo_after.input.transaction_id}#{master_utxo_after.input.index} "
          f"nonce={master_datum_after.nonce} token_count={master_datum_after.stats.total_token_count}")

    master_matches_tx = str(master_utxo_after.input.transaction_id) == tx_hash
    print(f"Master UTXO after-read matches the tx we just confirmed? {master_matches_tx}")

    return {
        "cycle": cycle_num, "success": True, "tx": tx_hash,
        "call_duration": call_duration, "master_matches_tx": master_matches_tx,
    }


def main():
    client = BareClient(DEPLOYMENT_JSON_PATH, PERM_KEYS_JSON_PATH, FUNDING_SIGNING_KEY)
    results = []
    for i in range(1, N_CYCLES + 1):
        results.append(run_one_mint(client, i))

    print(f"\n\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    passed = sum(1 for r in results if r.get("success"))
    print(f"Passed: {passed}/{N_CYCLES}")
    for r in results:
        if r.get("success"):
            print(f"  Cycle {r['cycle']}: OK, call={r['call_duration']:.1f}s, "
                  f"master_matches_tx={r['master_matches_tx']}")
        else:
            print(f"  Cycle {r['cycle']}: FAILED (call={r['call_duration']:.1f}s) - {str(r.get('error', '?'))[:150]}")


if __name__ == "__main__":
    main()