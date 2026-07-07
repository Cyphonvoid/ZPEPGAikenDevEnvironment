import json
import time
from CardanoClient import CardanoClient

DEPLOYMENT  = "testnet_deployment_ref.json"
PERM_KEYS   = "perm_keys.json"
FUNDING_KEY = "58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e"

client = CardanoClient(DEPLOYMENT, PERM_KEYS, FUNDING_KEY)

print("Pausing...")
res = client.pause()
print(res)

print("Resuming...")
res = client.resume()
print(res)