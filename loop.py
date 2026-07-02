import json
import time
from CardanoNetworkClient import CardanoNetworkClient, CardanoNet

INTERVAL_SECONDS = 5

pk = json.load(open('perm_keys.json'))
client = CardanoNetworkClient(
    deployment='testnet_deployment.json',
    funding_signing_key='58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e',
    operator_key=bytes.fromhex(pk['operator']['private_key_hex']),
    authority_key=bytes.fromhex(pk['authority']['private_key_hex']),
    owner_key=bytes.fromhex(pk['owner']['private_key_hex']),
    network_type=CardanoNet.TESTNET,
)

ITERATIONS = 10
results = []

print(f"Starting {ITERATIONS} pause/resume cycles with {INTERVAL_SECONDS}s interval")
print(f"Initial nonce: {client.get_master_state().datum.nonce}\n")

for i in range(ITERATIONS):
    print(f"--- Cycle {i+1}/{ITERATIONS} ---")
    pause_ok = resume_ok = False

    try:
        before = client.get_master_state()
        print(f"  nonce={before.datum.nonce} is_paused={before.datum.is_paused}")
        time.sleep(INTERVAL_SECONDS)
        r = client.pause()
        print(f"  pause:  OK  tx={r.tx_hash[:16]}")
        pause_ok = True
    except Exception as e:
        print(f"  pause:  FAIL")
        print(f"  ERROR: {e}")

    try:
        mid = client.get_master_state()
        print(f"  nonce={mid.datum.nonce} is_paused={mid.datum.is_paused}")
        time.sleep(INTERVAL_SECONDS)
        r = client.resume()
        print(f"  resume: OK  tx={r.tx_hash[:16]}")
        resume_ok = True
    except Exception as e:
        print(f"  resume: FAIL")
        print(f"  ERROR: {e}")

    after = client.get_master_state()
    print(f"  nonce after={after.datum.nonce} is_paused={after.datum.is_paused}")
    results.append((pause_ok, resume_ok))

pause_pass = sum(1 for p, r in results if p)
resume_pass = sum(1 for p, r in results if r)
print(f"\nPause:  {pause_pass}/10 passed")
print(f"Resume: {resume_pass}/10 passed")