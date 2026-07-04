"""
measure_lag_auto.py - Fully automated multi-cycle lag measurement.

Alternates pause/resume automatically for N cycles. Each cycle:
  1. Reads current master state to decide whether to call pause() or resume()
  2. Snapshots funding UTXOs immediately before the call
  3. Makes the call
  4. Snapshots master UTXO + funding UTXOs immediately after confirmation
  5. Polls funding address until it changes from the "immediately after"
     snapshot, timing exactly how long that takes (or times out)

No manual steps. No overlapping scripts. Nothing else should be touching
this wallet or contract while this runs, so any change detected during
polling can only be attributed to something this script itself did or
something external we did NOT expect - which itself would be useful
information.
"""

import time
from basic_client_v3 import BareClient
from CardanoDeployer.cardano_types import AikenTrue

DEPLOYMENT_JSON_PATH = "testnet_deployment.json"
PERM_KEYS_JSON_PATH = "perm_keys.json"
FUNDING_SIGNING_KEY = "58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e"

N_CYCLES = 15
POLL_INTERVAL_S = 2.0
POLL_TIMEOUT_S = 60.0


def snapshot_funding(client):
    utxos = client.context.utxos(client.funding_address)
    return {(str(u.input.transaction_id), u.input.index): u.output.amount.coin for u in utxos}


def run_one_cycle(client, cycle_num):
    print(f"\n{'='*60}")
    print(f"CYCLE {cycle_num}/{N_CYCLES}")
    print(f"{'='*60}")

    master_utxo_before, master_datum_before = client._get_master_utxo()
    is_paused_before = isinstance(master_datum_before.is_paused, AikenTrue)
    print(f"BEFORE: master={master_utxo_before.input.transaction_id}#{master_utxo_before.input.index} "
          f"nonce={master_datum_before.nonce} is_paused={is_paused_before}")

    funding_before = snapshot_funding(client)

    action = "resume" if is_paused_before else "pause"
    print(f"Calling: {action}()")

    start_call = time.monotonic()
    if action == "resume":
        ok, tx_hash, err = client.resume()
    else:
        ok, tx_hash, err = client.pause()
    call_duration = time.monotonic() - start_call

    print(f"success={ok} tx={tx_hash} call_duration={call_duration:.1f}s")
    if err:
        print(f"error={err}")
        return {"cycle": cycle_num, "action": action, "success": False, "error": err}

    master_utxo_after, master_datum_after = client._get_master_utxo()
    is_paused_after = isinstance(master_datum_after.is_paused, AikenTrue)
    print(f"AFTER:  master={master_utxo_after.input.transaction_id}#{master_utxo_after.input.index} "
          f"nonce={master_datum_after.nonce} is_paused={is_paused_after}")

    master_matches_tx = str(master_utxo_after.input.transaction_id) == tx_hash
    print(f"Master UTXO after-read matches the tx we just confirmed? {master_matches_tx}")

    funding_immediately_after = snapshot_funding(client)
    funding_changed_immediately = funding_immediately_after != funding_before
    print(f"Funding set already reflects the change immediately? {funding_changed_immediately}")

    poll_start = time.monotonic()
    poll_count = 0
    changed_during_poll = False
    poll_elapsed = 0.0
    while True:
        poll_count += 1
        poll_elapsed = time.monotonic() - poll_start
        current = snapshot_funding(client)
        if current != funding_immediately_after:
            changed_during_poll = True
            print(f"Funding set changed during poll after {poll_elapsed:.1f}s ({poll_count} polls) "
                  f"- UNEXPECTED, nothing else should be running")
            break
        if poll_elapsed > POLL_TIMEOUT_S:
            print(f"Funding set stable for the full {POLL_TIMEOUT_S}s poll window ({poll_count} polls) - expected")
            break
        time.sleep(POLL_INTERVAL_S)

    return {
        "cycle": cycle_num, "action": action, "success": True, "tx": tx_hash,
        "call_duration": call_duration, "master_matches_tx": master_matches_tx,
        "funding_changed_immediately": funding_changed_immediately,
        "changed_during_poll": changed_during_poll, "poll_elapsed": poll_elapsed,
    }


def main():
    client = BareClient(DEPLOYMENT_JSON_PATH, PERM_KEYS_JSON_PATH, FUNDING_SIGNING_KEY)
    results = []
    for i in range(1, N_CYCLES + 1):
        results.append(run_one_cycle(client, i))

    print(f"\n\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    passed = sum(1 for r in results if r.get("success"))
    print(f"Passed: {passed}/{N_CYCLES}")
    for r in results:
        if r.get("success"):
            print(f"  Cycle {r['cycle']} ({r['action']}): OK, "
                  f"call={r['call_duration']:.1f}s, "
                  f"master_matches_tx={r['master_matches_tx']}, "
                  f"funding_changed_immediately={r['funding_changed_immediately']}, "
                  f"unexpected_change_during_poll={r['changed_during_poll']}")
        else:
            print(f"  Cycle {r['cycle']} ({r['action']}): FAILED - {r.get('error', '?')[:100]}")


if __name__ == "__main__":
    main()