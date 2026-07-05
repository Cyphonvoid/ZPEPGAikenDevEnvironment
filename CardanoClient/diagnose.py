"""
diagnose.py - Bypass Blockfrost evaluator for any operation to get
real node trace output. Set OPERATION and args below, run, read traces.
"""

from pycardano.plutus import ExecutionUnits
from CardanoClient import CardanoClient

DEPLOYMENT  = "deployment_ref_2026-07-05_09-33-37.json"
PERM_KEYS   = "perm_keys.json"
FUNDING_KEY = "58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e"

client = CardanoClient(DEPLOYMENT, PERM_KEYS, FUNDING_KEY, network="preprod")

result = client.resume()
print(result)
exit()

# Bypass evaluator — return generous fixed execution units
def _bypass_evaluate(cbor):
    return {
        "spend:0": ExecutionUnits(mem=14_000_000, steps=10_000_000_000),
        "mint:0":  ExecutionUnits(mem=14_000_000, steps=10_000_000_000),
    }

client._backend._context.evaluate_tx_cbor = _bypass_evaluate

# ── Set operation to diagnose ─────────────────────────────────────────
# Uncomment one:

result = client.pause()
print(result)


# result = client.resume()
result = client.mint(
    cross_chain_global_id="diagnose-mint",
    sha256_hash="ab" * 32,
    upload_date="2026-07-05T00:00:00Z",
    version=1,
    token_data={"diagnose": True},
)

# result = client.withdraw(amount_lovelace=2_000_000)
# result = {"success": False, "error": "No operation selected — uncomment one above."}
import json
print(json.dumps({k: v for k, v in result.items() if k != "receipt_json"}, indent=2))