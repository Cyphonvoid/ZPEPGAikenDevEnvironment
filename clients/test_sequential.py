"""
test_sequential.py - Sequential functional test for all CardanoNetworkClient
write operations, relying on client retry logic for reliability.
"""

import json
import sys
import time
from pathlib import Path
from typing import Optional

from CardanoNetworkClient_v5 import CardanoNetworkClient, CardanoNet, MissingKeyError
from CardanoDeployer.cardano_types import AikenTrue, AikenFalse, NoneChainLink, SomeChainLink
from nacl.signing import SigningKey

# ── Config ────────────────────────────────────────────────────────────────────

DEPLOYMENT_JSON_PATH = "testnet_deployment.json"
PERM_KEYS_JSON_PATH  = "perm_keys.json"
FUNDING_SIGNING_KEY  = "58200e0d160a055b49f5f0b3f3de26b87ebf51cde2ce3036b9fffe4acdc7a805d71e"
NETWORK_TYPE         = CardanoNet.TESTNET

TEST_GLOBAL_ID       = b"seq-test-cross-chain-id-0001"
TEST_SHA256          = bytes.fromhex("a" * 64)
TEST_UPLOAD_DATE     = b"2026-07-02T00:00:00Z"
TEST_TOKEN_DATA      = b'{"title": "Sequential write test"}'
WITHDRAW_AMOUNT      = 2_000_000

FWD_SCRIPT_ADDR      = bytes.fromhex("55" * 28)
FWD_POLICY_ID        = bytes.fromhex("66" * 28)
FWD_LINK_REASON      = b"seq-test-forward"
FWD_LINKED_AT        = 1_950_000_000
FWD_INSTRUCTIONS     = b'{"note": "seq test forward"}'

BWD_SCRIPT_ADDR      = bytes.fromhex("77" * 28)
BWD_POLICY_ID        = bytes.fromhex("88" * 28)
BWD_LINK_REASON      = b"seq-test-backward"
BWD_LINKED_AT        = 1_850_000_000
BWD_INSTRUCTIONS     = b'{"note": "seq test backward"}'

# ── Helpers ───────────────────────────────────────────────────────────────────

passed = 0
failed = 0

def run(name: str, fn) -> bool:
    global passed, failed
    print(f"\n[{name}]")
    sys.stdout.flush()
    start = time.monotonic()
    try:
        result = fn()
        duration = time.monotonic() - start
        if hasattr(result, "success"):
            if result.success:
                print(f"  PASS ({duration:.1f}s)  tx={result.tx_hash[:16] if result.tx_hash else '?'}  attempts={result.attempts}")
                passed += 1
                return True
            else:
                print(f"  FAIL ({duration:.1f}s)  attempts={result.attempts}  error={str(result.error)[:120]}")
                failed += 1
                return False
        else:
            print(f"  PASS ({duration:.1f}s)  {result}")
            passed += 1
            return True
    except Exception as e:
        duration = time.monotonic() - start
        print(f"  FAIL ({duration:.1f}s)  {type(e).__name__}: {str(e)[:120]}")
        failed += 1
        return False


# ── Setup ─────────────────────────────────────────────────────────────────────

print("=== Sequential Write Test ===")

perm_keys = json.loads(Path(PERM_KEYS_JSON_PATH).read_text())
client = CardanoNetworkClient(
    deployment=DEPLOYMENT_JSON_PATH,
    funding_signing_key=FUNDING_SIGNING_KEY,
    operator_key=bytes.fromhex(perm_keys["operator"]["private_key_hex"]),
    authority_key=bytes.fromhex(perm_keys["authority"]["private_key_hex"]),
    owner_key=bytes.fromhex(perm_keys["owner"]["private_key_hex"]),
    network_type=NETWORK_TYPE,
)

# ── Read tests ────────────────────────────────────────────────────────────────

run("get_master_state", lambda: (
    lambda s: f"nonce={s.datum.nonce} is_paused={s.datum.is_paused}"
)(client.get_master_state()))

run("get_stats", lambda: (
    lambda s: f"token_count={s.total_token_count} unique={s.total_unique_documents}"
)(client.get_stats()))

# ── Write: mint_document ──────────────────────────────────────────────────────

def _mint():
    before = client.get_master_state()
    return client.mint_document(
        cross_chain_global_id=TEST_GLOBAL_ID, sha256_hash=TEST_SHA256,
        upload_date=TEST_UPLOAD_DATE, version=1, token_data=TEST_TOKEN_DATA,
        is_unique_document=True, valid_lower_bound=before.datum.nonce,
    )
run("mint_document", _mint)

# ── Summary ───────────────────────────────────────────────────────────────────

total = passed + failed
print(f"\n{'='*50}")
print(f"TOTAL: {total}  PASSED: {passed}  FAILED: {failed}")
print(f"{'='*50}")
sys.exit(0 if failed == 0 else 1)
# ── Write: pause ──────────────────────────────────────────────────────────────

def _pause():
    before = client.get_master_state()
    if isinstance(before.datum.is_paused, AikenTrue):
        return "SKIPPED - already paused"
    return client.pause()
run("pause", _pause)

# ── Write: resume ─────────────────────────────────────────────────────────────

def _resume():
    before = client.get_master_state()
    if isinstance(before.datum.is_paused, AikenFalse):
        return "SKIPPED - already resumed"
    return client.resume()
run("resume", _resume)

# ── Write: rotate_key (round-trip) ───────────────────────────────────────────

def _rotate_to_throwaway():
    throwaway_pub = bytes(SigningKey.generate().verify_key)
    return client.rotate_key("operator", throwaway_pub)
run("rotate_key (to throwaway)", _rotate_to_throwaway)

def _rotate_back():
    original_pub = bytes.fromhex(perm_keys["operator"]["public_key_hex"])
    return client.rotate_key("operator", original_pub)
run("rotate_key (back to original)", _rotate_back)

# ── Write: withdraw ───────────────────────────────────────────────────────────

def _withdraw():
    return client.withdraw(amount=WITHDRAW_AMOUNT)
run("withdraw", _withdraw)

# ── Write: link_forward (one-time) ───────────────────────────────────────────

def _link_forward():
    before = client.get_master_state()
    if not isinstance(before.datum.forward_link, NoneChainLink):
        return "SKIPPED - forward_link already set"
    return client.link_forward(
        next_script_address=FWD_SCRIPT_ADDR, next_policy_id=FWD_POLICY_ID,
        link_reason=FWD_LINK_REASON, linked_at=FWD_LINKED_AT,
        instructions=FWD_INSTRUCTIONS,
    )
run("link_forward", _link_forward)

# ── Write: link_backward (one-time) ──────────────────────────────────────────

def _link_backward():
    before = client.get_master_state()
    if not isinstance(before.datum.backward_link, NoneChainLink):
        return "SKIPPED - backward_link already set"
    return client.link_backward(
        prev_script_address=BWD_SCRIPT_ADDR, prev_policy_id=BWD_POLICY_ID,
        link_reason=BWD_LINK_REASON, linked_at=BWD_LINKED_AT,
        instructions=BWD_INSTRUCTIONS,
    )
run("link_backward", _link_backward)

# ── Non-write: MissingKeyError ────────────────────────────────────────────────

def _missing_key():
    op_only = CardanoNetworkClient(
        deployment=client.deployment,
        funding_signing_key=FUNDING_SIGNING_KEY,
        operator_key=b"\x00" * 32,
        network_type=NETWORK_TYPE,
    )
    try:
        op_only.pause()
        raise AssertionError("should have raised MissingKeyError")
    except MissingKeyError as e:
        return f"MissingKeyError raised correctly"
run("MissingKeyError check", _missing_key)

# ── Summary ───────────────────────────────────────────────────────────────────

total = passed + failed
print(f"\n{'='*50}")
print(f"TOTAL: {total}  PASSED: {passed}  FAILED: {failed}")
print(f"{'='*50}")
sys.exit(0 if failed == 0 else 1)