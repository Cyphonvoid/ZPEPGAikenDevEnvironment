import json
from pycardano import PlutusV3Script, ScriptHash, Address, Network

with open('zpepg_aiken_registry/plutus.json') as f:
    blueprint = json.load(f)

# All three entries share the same compiled code/hash - just grab validator 0
validator = blueprint['validators'][0]

script_bytes = PlutusV3Script(bytes.fromhex(validator['compiledCode']))
script_hash = ScriptHash(bytes.fromhex(validator['hash']))

policy_id = script_hash
script_address = Address(payment_part=script_hash, network=Network.TESTNET)

print("Policy ID:", policy_id)
print("Script Address:", script_address)