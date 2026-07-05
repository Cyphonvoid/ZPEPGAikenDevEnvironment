import time
import json
from basic_client_v4 import BareClient
from CardanoDeployer.cardano_types import AikenTrue

DEPLOYMENT_JSON_PATH = "testnet_deployment.json"
PERM_KEYS_JSON_PATH = "perm_keys.json"
FUNDING_SIGNING_KEY = "58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e"

TOTAL_CYCLES = 15
PAUSE_RESUME_CYCLES = 3
POLL_INTERVAL_S = 2.0
POLL_TIMEOUT_S = 60.0

LOG_FILE = "stress_full_log.txt"


def _pause_resume_cycle_numbers(total, pause_resume_count):
    if pause_resume_count == 0:
        return set()
    step = total / pause_resume_count
    return {round(step * i + step / 2) for i in range(pause_resume_count)}


def snapshot_funding(client):
    utxos = client.context.utxos(client.funding_address)
    return {(str(u.input.transaction_id), u.input.index): u.output.amount.coin for u in utxos}


log_lines = []

def log(msg, full_msg=None):
    """Print truncated to terminal, save full to log."""
    print(msg)
    log_lines.append(full_msg if full_msg is not None else msg)


def flush_log():
    with open(LOG_FILE, "w") as f:
        f.write("\n".join(log_lines))


def run_one_cycle(client, cycle_num, do_pause_resume, mint_counter):
    log(f"\n{'='*60}")
    log(f"CYCLE {cycle_num}/{TOTAL_CYCLES}")
    log(f"{'='*60}")

    master_utxo_before, datum_before = client._get_master_utxo()
    is_paused = isinstance(datum_before.is_paused, AikenTrue)
    log(f"BEFORE: nonce={datum_before.nonce} is_paused={is_paused} "
        f"token_count={datum_before.stats.total_token_count}")

    funding_before = snapshot_funding(client)

    if is_paused:
        action = "resume"
    elif do_pause_resume:
        action = "pause"
    else:
        action = "mint"

    log(f"Calling: {action}()")
    start_call = time.monotonic()

    if action == "mint":
        ok, tx_hash, err = client.mint(
            cross_chain_global_id=f"stress-mint-cycle-{cycle_num}-#{mint_counter}".encode(),
            sha256_hash=bytes([cycle_num % 256]) * 32,
            upload_date=b"2026-07-04T00:00:00Z",
            version=1,
            token_data=f'{{"cycle": {cycle_num}, "mint_n": {mint_counter}}}'.encode(),
        )
    elif action == "resume":
        ok, tx_hash, err = client.resume()
    else:
        ok, tx_hash, err = client.pause()

    call_duration = time.monotonic() - start_call

    short_err = (err[:120] + "...") if err and len(err) > 120 else err
    log(f"success={ok} tx={tx_hash} call_duration={call_duration:.1f}s",
        full_msg=f"success={ok} tx={tx_hash} call_duration={call_duration:.1f}s")

    if err:
        log(f"error={short_err}", full_msg=f"FULL ERROR:\n{err}")
        flush_log()
        return {"cycle": cycle_num, "action": action, "success": False, "error": err}

    master_utxo_after, datum_after = client._get_master_utxo()
    is_paused_after = isinstance(datum_after.is_paused, AikenTrue)
    log(f"AFTER:  nonce={datum_after.nonce} is_paused={is_paused_after} "
        f"token_count={datum_after.stats.total_token_count}")

    master_matches_tx = str(master_utxo_after.input.transaction_id) == tx_hash
    log(f"Master UTXO matches confirmed tx? {master_matches_tx}")

    funding_immediately_after = snapshot_funding(client)
    funding_changed_immediately = funding_immediately_after != funding_before
    log(f"Funding set reflects change immediately? {funding_changed_immediately}")

    poll_start = time.monotonic()
    poll_count = 0
    changed_during_poll = False
    while True:
        poll_count += 1
        poll_elapsed = time.monotonic() - poll_start
        current = snapshot_funding(client)
        if current != funding_immediately_after:
            changed_during_poll = True
            log(f"Funding set changed unexpectedly after {poll_elapsed:.1f}s ({poll_count} polls)")
            break
        if poll_elapsed > POLL_TIMEOUT_S:
            log(f"Funding set stable for full {POLL_TIMEOUT_S}s ({poll_count} polls) - expected")
            break
        time.sleep(POLL_INTERVAL_S)

    flush_log()
    return {
        "cycle": cycle_num, "action": action, "success": True, "tx": tx_hash,
        "call_duration": call_duration, "master_matches_tx": master_matches_tx,
        "funding_changed_immediately": funding_changed_immediately,
        "changed_during_poll": changed_during_poll,
    }


def main():
    client = BareClient(DEPLOYMENT_JSON_PATH, PERM_KEYS_JSON_PATH, FUNDING_SIGNING_KEY)

    pause_resume_cycles = _pause_resume_cycle_numbers(TOTAL_CYCLES, PAUSE_RESUME_CYCLES)
    log(f"Pause/resume will occur at cycles: {sorted(pause_resume_cycles)}")
    log(f"All other {TOTAL_CYCLES - PAUSE_RESUME_CYCLES} cycles will mint.\n")

    results = []
    mint_counter = 0

    for i in range(1, TOTAL_CYCLES + 1):
        do_pause_resume = i in pause_resume_cycles
        if not do_pause_resume:
            mint_counter += 1
        result = run_one_cycle(client, i, do_pause_resume, mint_counter)
        results.append(result)

    summary_lines = [
        f"\n\n{'='*60}",
        "SUMMARY",
        f"{'='*60}",
    ]
    passed = sum(1 for r in results if r.get("success"))
    summary_lines.append(f"Passed: {passed}/{TOTAL_CYCLES}")
    for r in results:
        if r.get("success"):
            line = (f"  Cycle {r['cycle']} ({r['action']}): OK "
                    f"call={r['call_duration']:.1f}s "
                    f"master_matches_tx={r['master_matches_tx']} "
                    f"funding_immediate={r['funding_changed_immediately']} "
                    f"unexpected_poll_change={r['changed_during_poll']}")
        else:
            short = r.get('error', '?')[:80]
            line = f"  Cycle {r['cycle']} ({r['action']}): FAILED - {short}..."
        summary_lines.append(line)

    for line in summary_lines:
        log(line)

    flush_log()
    print(f"\nFull log written to {LOG_FILE}")


if __name__ == "__main__":
    main()