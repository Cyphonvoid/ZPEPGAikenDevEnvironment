"""
test_bare_client.py - Runs pause/resume in a loop against BareClient.
No abstractions. Prints full raw result for every single call.
"""

import json
from pathlib import Path
from basic_client import BareClient
import time

DEPLOYMENT_JSON_PATH = "testnet_deployment.json"
PERM_KEYS_JSON_PATH = "perm_keys.json"
FUNDING_SIGNING_KEY = "58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e"

client = BareClient(DEPLOYMENT_JSON_PATH, PERM_KEYS_JSON_PATH, FUNDING_SIGNING_KEY)

N_CYCLES = 1
results = []

for i in range(1, N_CYCLES + 1):
    print(f"\n===== CYCLE {i}/{N_CYCLES} =====")


    ok, tx, err = client.pause()
    print(f"success={ok} tx={tx}")
    if err:
        print(f"error={err}")
        
    exit()
    print(f"--- RESUME ---")
    time.sleep(10)
    debug_utxo, debug_datum = client._get_master_utxo()
    print(f"Resume is about to spend UTXO: {debug_utxo.input.transaction_id}#{debug_utxo.input.index}")
    ok, tx, err = client.resume()
    print(f"success={ok} tx={tx}")
    if err:
        print(f"error={err}")
    if ok:
        post_resume_utxo, post_resume_datum = client._get_master_utxo()
        print(f"Immediately after Resume confirmed, master UTXO is: {post_resume_utxo.input.transaction_id}#{post_resume_utxo.input.index}")
        print(f"nonce={post_resume_datum.nonce} is_paused={post_resume_datum.is_paused}")

    results.append(("resume", ok))

    print(f"--- PAUSE ---")
    time.sleep(10)
    debug_utxo, debug_datum = client._get_master_utxo()
    print(f"Pause is about to spend UTXO: {debug_utxo.input.transaction_id}#{debug_utxo.input.index}")
    print(f"That UTXO's nonce: {debug_datum.nonce}  is_paused: {debug_datum.is_paused}")
    ok, tx, err = client.pause()
    print(f"success={ok} tx={tx}")
    if err:
        print(f"error={err}")
    results.append(("pause", ok))

total = len(results)
passed = sum(1 for _, ok in results if ok)
print(f"\n{'='*50}")
print(f"TOTAL: {passed}/{total} passed")
print(f"{'='*50}")