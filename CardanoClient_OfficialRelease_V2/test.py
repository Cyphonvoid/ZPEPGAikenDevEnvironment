import json
import time
from pathlib import Path
from CardanoClient import CardanoClient
DEPLOYMENT  = "deployment_ref_2026-07-06_10-01-25.json"  # update to your v2 ref json
PERM_KEYS   = "perm_keys.json"
FUNDING_KEY = "58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e"
FUNDING_ADDR = "addr_test1vq2aeqdjc9m40zas6k6sa00nvqd4m9sh67c3ujjxx2vn4lg5a4mvw"

client = CardanoClient(DEPLOYMENT, PERM_KEYS, FUNDING_KEY, network="preprod")
res = client.withdraw_extra_funds(to_address=FUNDING_ADDR, amount_lovelace=20_000_000)

print(json.dumps(res, indent=2))