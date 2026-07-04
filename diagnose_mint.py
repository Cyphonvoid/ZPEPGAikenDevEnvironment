"""
diagnose_mint.py - One-off diagnostic: bypass Blockfrost's evaluator for
a single mint() call so the transaction goes straight to submission,
forcing the real Cardano node to return the actual, specific validation
failure reason instead of Blockfrost's uninformative empty ScriptFailures.

This does NOT modify basic_client_v3.py - it monkeypatches the evaluate
method on the already-constructed client instance's context, only for
the duration of this one script.
"""

from basic_client_v3 import BareClient
from pycardano.plutus import ExecutionUnits

DEPLOYMENT_JSON_PATH = "testnet_deployment.json"
PERM_KEYS_JSON_PATH = "perm_keys.json"
FUNDING_SIGNING_KEY = "58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e"


def main():
    client = BareClient(DEPLOYMENT_JSON_PATH, PERM_KEYS_JSON_PATH, FUNDING_SIGNING_KEY)

    # Bypass evaluation entirely for this one diagnostic run - hand back
    # generous fixed execution units so build_and_sign skips the real
    # evaluate call and submits directly. The node will then run the
    # actual script and return a specific, detailed error if it rejects.
    def _bypass_evaluate(cbor):
        return {
            "spend:0": ExecutionUnits(mem=5_500_000, steps=3_300_000_000),
            "mint:0": ExecutionUnits(mem=5_500_000, steps=3_300_000_000),
        }

    client.context.evaluate_tx_cbor = _bypass_evaluate

    master_utxo, master_datum = client._get_master_utxo()
    print(f"Current master state: nonce={master_datum.nonce}, "
          f"is_paused={master_datum.is_paused}, "
          f"token_count={master_datum.stats.total_token_count}")

    print("\nAttempting mint() with evaluator bypassed...\n")
    ok, tx_hash, err = client.mint(
        cross_chain_global_id=b"diagnose-mint-bypass-test",
        sha256_hash=bytes([1]) * 32,
        upload_date=b"2026-07-03T00:00:00Z",
        version=1,
        token_data=b'{"diagnostic": true}',
    )

    print(f"success={ok}")
    print(f"tx={tx_hash}")
    if err:
        print(f"\nFULL ERROR (this is the real node's detailed rejection reason):")
        print(err)


if __name__ == "__main__":
    main()