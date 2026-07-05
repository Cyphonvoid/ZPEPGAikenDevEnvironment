from CardanoClient import CardanoClient
from CardanoDeployer.cardano_types import AikenTrue
import time

DEPLOYMENT = '/workspaces/ZPEPGAikenDevEnvironment/testnet_deployment_ref.json'
PERM_KEYS = '/workspaces/ZPEPGAikenDevEnvironment/perm_keys.json'
FUNDING_KEY = '58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e'

c = CardanoClient(DEPLOYMENT, PERM_KEYS, FUNDING_KEY)

TOTAL = 10
PAUSE_RESUME_AT = {2, 8, 12}

results = []
mint_n = 0
for i in range(1, TOTAL + 1):
    state = c.get_master_state()
    is_paused = state['is_paused']

    if is_paused:
        action = 'resume'
        r = c.resume()
    elif i in PAUSE_RESUME_AT:
        action = 'pause'
        r = c.pause()
    else:
        mint_n += 1
        action = 'mint'
        r = c.mint(
            cross_chain_global_id=f'stress-ref-cycle-{i}-{mint_n}',
            sha256_hash='ab' * 32,
            upload_date='2026-07-04T00:00:00Z',
            version=1,
            token_data={'cycle': i, 'mint_n': mint_n},
        )

    print(f'Cycle {i:2d} ({action}): success={r.success} tx={r.tx_hash}')
    if r.error:
        print(f'  ERROR: {r.error[:120]}')
    results.append(r.success)

passed = sum(results)
print(f'\nPassed: {passed}/{TOTAL}')