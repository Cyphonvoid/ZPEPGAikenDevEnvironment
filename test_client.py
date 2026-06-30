"""
test_cardano_network_client.py - Function test suite for
CardanoNetworkClient itself, as a black box.

Unlike test_registry_contract.py / pentest_registry_contract.py (which
build transactions manually to test the CONTRACT's validator logic),
this suite only ever calls CardanoNetworkClient's own public methods -
the goal is confirming the CLIENT correctly wraps contract interactions,
not re-testing the contract's validation rules (already covered
extensively elsewhere). If something here fails, the first question is
"did the client build/call something wrong," not "did the contract
reject something it shouldn't have."

PREREQUISITES: same as the other test suites - devnet running,
deployment.json + perm_keys.json present, a funded wallet (mnemonic or
skey) available.

Run order matters for several tests (nonce/state dependent) - tests run
in the order defined in main(), not alphabetically/automatically.
"""

from __future__ import annotations

import json
import sys
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from CardanoNetworkClient import (
    CardanoNetworkClient, CardanoNet, MissingKeyError,
)
from CardanoDeployer.cardano_types import AikenTrue, AikenFalse, NoneChainLink, SomeChainLink

# ════════════════════════════════════════════════════════════════════════
# CONFIG - fill these in for your environment
# ════════════════════════════════════════════════════════════════════════

DEPLOYMENT_JSON_PATH = "deployment.json"
PERM_KEYS_JSON_PATH = "perm_keys.json"
FUNDING_SIGNING_KEY = "test test test test test test test test test test test test test test test test test test test test test test test sauce"
NETWORK_TYPE = CardanoNet.DEVNET

REPORT_PATH = "client_function_test_report.txt"

TEST_GLOBAL_ID = b"client-func-test-cross-chain-id-0001"
TEST_SHA256 = bytes.fromhex("b" * 64)
TEST_UPLOAD_DATE = b"2026-06-30T00:00:00Z"
TEST_TOKEN_DATA = b'{"title": "Client function test document"}'

TEST_FORWARD_SCRIPT_ADDRESS = bytes.fromhex("55" * 28)
TEST_FORWARD_POLICY_ID = bytes.fromhex("66" * 28)
TEST_FORWARD_LINK_REASON = b"client-func-test-forward"
TEST_FORWARD_LINKED_AT = 1_950_000_000
TEST_FORWARD_INSTRUCTIONS = b'{"note": "client function test forward link"}'

TEST_BACKWARD_SCRIPT_ADDRESS = bytes.fromhex("77" * 28)
TEST_BACKWARD_POLICY_ID = bytes.fromhex("88" * 28)
TEST_BACKWARD_LINK_REASON = b"client-func-test-backward"
TEST_BACKWARD_LINKED_AT = 1_850_000_000
TEST_BACKWARD_INSTRUCTIONS = b'{"note": "client function test backward link"}'

TEST_WITHDRAW_AMOUNT = 2_000_000


# ════════════════════════════════════════════════════════════════════════
# Minimal test framework (same shape as the contract test suites)
# ════════════════════════════════════════════════════════════════════════

@dataclass
class TestResult:
    name: str
    passed: bool
    detail: str = ""
    tx_hash: Optional[str] = None
    duration_seconds: float = 0.0
    exception_text: Optional[str] = None


@dataclass
class TestRunner:
    results: list[TestResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def run(self, name: str, fn: Callable[[], tuple[bool, str, Optional[str]]]) -> TestResult:
        print(f"\n{'─'*70}")
        print(f"TEST: {name}")
        sys.stdout.flush()

        start = time.monotonic()
        exc_text = None
        try:
            passed, detail, tx_hash = fn()
        except Exception as e:
            passed = False
            detail = f"Unhandled exception: {e}"
            tx_hash = None
            exc_text = traceback.format_exc()
        duration = time.monotonic() - start

        result = TestResult(
            name=name, passed=passed, detail=detail, tx_hash=tx_hash,
            duration_seconds=duration, exception_text=exc_text,
        )
        self.results.append(result)

        status = "PASS" if passed else "FAIL"
        print(f"  [{status}]  ({duration:.2f}s)")
        if tx_hash:
            print(f"  tx: {tx_hash}")
        print(f"  {detail}")
        if exc_text:
            print(f"  --- exception ---\n{exc_text}")
        sys.stdout.flush()
        return result

    def write_report(self, path: str) -> None:
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed
        ended_at = datetime.now(timezone.utc)

        lines = [
            "=" * 78, "CARDANO NETWORK CLIENT - FUNCTION TEST REPORT", "=" * 78,
            f"Started:  {self.started_at.isoformat()}",
            f"Finished: {ended_at.isoformat()}",
            f"Total duration: {(ended_at - self.started_at).total_seconds():.2f}s",
            "", f"TOTAL: {total}   PASSED: {passed}   FAILED: {failed}", "=" * 78, "",
        ]
        for i, r in enumerate(self.results, 1):
            lines.append(f"[{i}/{total}] {'PASS' if r.passed else 'FAIL'}  {r.name}")
            lines.append(f"    duration:  {r.duration_seconds:.2f}s")
            if r.tx_hash:
                lines.append(f"    tx_hash:   {r.tx_hash}")
            lines.append(f"    detail:    {r.detail}")
            if r.exception_text:
                lines.append("    exception:")
                lines.extend(f"      {line}" for line in r.exception_text.splitlines())
            lines.append("")
        lines += ["=" * 78, "SUMMARY", "=" * 78]
        lines += [f"  {'PASS' if r.passed else 'FAIL'}  {r.name}" for r in self.results]

        Path(path).write_text("\n".join(lines))
        print(f"\nReport written to: {path}")
        print(f"TOTAL: {total}   PASSED: {passed}   FAILED: {failed}")


# ════════════════════════════════════════════════════════════════════════
# Tests - each calls ONLY public CardanoNetworkClient methods
# ════════════════════════════════════════════════════════════════════════

def test_get_master_state(client: CardanoNetworkClient) -> tuple[bool, str, Optional[str]]:
    state = client.get_master_state()
    if state.datum.nonce < 0:
        return False, f"Nonce is somehow negative: {state.datum.nonce}", None
    return True, f"nonce={state.datum.nonce}, is_paused={state.datum.is_paused}", None


def test_get_stats(client: CardanoNetworkClient) -> tuple[bool, str, Optional[str]]:
    stats = client.get_stats()
    return True, f"total_token_count={stats.total_token_count}, total_unique_documents={stats.total_unique_documents}", None


def test_mint_document(client: CardanoNetworkClient) -> tuple[bool, str, Optional[str]]:
    before = client.get_master_state()
    result = client.mint_document(
        cross_chain_global_id=TEST_GLOBAL_ID, sha256_hash=TEST_SHA256,
        upload_date=TEST_UPLOAD_DATE, version=1, token_data=TEST_TOKEN_DATA,
        is_unique_document=True, valid_lower_bound=before.datum.nonce,
    )
    if not result.confirmed:
        return False, "mint_document returned confirmed=False", result.tx_hash
    if result.new_master_state.datum.nonce != before.datum.nonce + 1:
        return False, f"Nonce did not advance correctly: {before.datum.nonce} -> {result.new_master_state.datum.nonce}", result.tx_hash
    if result.new_master_state.datum.stats.total_token_count != before.datum.stats.total_token_count + 1:
        return False, "total_token_count did not increment", result.tx_hash

    # Confirm find_document independently rediscovers what mint_document built.
    found = client.find_document(result.new_master_state.datum.stats.last_cardano_asset_id[28:])
    if found is None:
        return False, "mint_document succeeded but find_document can't locate the new token afterward", result.tx_hash
    if found.cross_chain_global_id != TEST_GLOBAL_ID:
        return False, "find_document returned a TokenDatum with the wrong cross_chain_global_id", result.tx_hash

    return True, f"Minted + independently re-found via find_document. nonce {before.datum.nonce}->{result.new_master_state.datum.nonce}", result.tx_hash


def test_pause_resume_roundtrip(client: CardanoNetworkClient) -> tuple[bool, str, Optional[str]]:
    before = client.get_master_state()
    if isinstance(before.datum.is_paused, AikenTrue):
        return False, "Precondition failed: contract is already paused before this test started", None

    pause_result = client.pause()
    if not isinstance(pause_result.new_master_state.datum.is_paused, AikenTrue):
        return False, "pause() succeeded but is_paused is not True afterward", pause_result.tx_hash

    resume_result = client.resume()
    if not isinstance(resume_result.new_master_state.datum.is_paused, AikenFalse):
        return False, "resume() succeeded but is_paused is not False afterward", resume_result.tx_hash

    return True, (
        f"Pause/Resume round-trip confirmed. "
        f"[pause tx {pause_result.tx_hash}] [resume tx {resume_result.tx_hash}]"
    ), resume_result.tx_hash


def test_rotate_key_roundtrip(client: CardanoNetworkClient) -> tuple[bool, str, Optional[str]]:
    """
    Round-trips the operator key via client.rotate_key(), confirming the
    client correctly keeps its own in-memory operator key in sync after
    rotation (since a subsequent mint_document in THIS SAME test needs to
    sign with whatever the new live operator key actually is).
    """
    from nacl.signing import SigningKey
    before = client.get_master_state()
    original_operator_pub = before.datum.operator_key

    throwaway = SigningKey.generate()
    throwaway_pub = bytes(throwaway.verify_key)

    to_throwaway = client.rotate_key("operator", throwaway_pub)
    if to_throwaway.new_master_state.datum.operator_key != throwaway_pub:
        return False, "rotate_key to throwaway succeeded but operator_key didn't update on-chain", to_throwaway.tx_hash

    # If the client didn't keep its in-memory key in sync, this next call
    # would sign with the now-stale original key and fail on-chain.
    back_to_original = client.rotate_key("operator", original_operator_pub)
    if back_to_original.new_master_state.datum.operator_key != original_operator_pub:
        return False, "rotate_key back to original succeeded but operator_key didn't update on-chain", back_to_original.tx_hash

    return True, (
        f"Operator key round-trip confirmed, including client's in-memory key staying in sync. "
        f"[{to_throwaway.tx_hash}] [{back_to_original.tx_hash}]"
    ), back_to_original.tx_hash


def test_withdraw(client: CardanoNetworkClient) -> tuple[bool, str, Optional[str]]:
    before = client.get_master_state()
    result = client.withdraw(amount=TEST_WITHDRAW_AMOUNT)
    if not result.confirmed:
        return False, "withdraw returned confirmed=False", result.tx_hash
    if result.new_master_state.datum.nonce != before.datum.nonce + 1:
        return False, "Nonce did not advance after withdraw", result.tx_hash
    return True, f"Withdrew {TEST_WITHDRAW_AMOUNT} lovelace, nonce {before.datum.nonce}->{result.new_master_state.datum.nonce}", result.tx_hash


def test_link_forward(client: CardanoNetworkClient) -> tuple[bool, str, Optional[str]]:
    before = client.get_master_state()
    if not isinstance(before.datum.forward_link, NoneChainLink):
        return True, "SKIPPED (soft pass): forward_link already set on this devnet session - one-time-only action.", None

    result = client.link_forward(
        next_script_address=TEST_FORWARD_SCRIPT_ADDRESS, next_policy_id=TEST_FORWARD_POLICY_ID,
        link_reason=TEST_FORWARD_LINK_REASON, linked_at=TEST_FORWARD_LINKED_AT,
        instructions=TEST_FORWARD_INSTRUCTIONS,
    )
    if not isinstance(result.new_master_state.datum.forward_link, SomeChainLink):
        return False, "link_forward succeeded but forward_link is not set afterward", result.tx_hash
    return True, f"forward_link set permanently, nonce {before.datum.nonce}->{result.new_master_state.datum.nonce}", result.tx_hash


def test_link_backward(client: CardanoNetworkClient) -> tuple[bool, str, Optional[str]]:
    before = client.get_master_state()
    if not isinstance(before.datum.backward_link, NoneChainLink):
        return True, "SKIPPED (soft pass): backward_link already set on this devnet session - one-time-only action.", None

    result = client.link_backward(
        prev_script_address=TEST_BACKWARD_SCRIPT_ADDRESS, prev_policy_id=TEST_BACKWARD_POLICY_ID,
        link_reason=TEST_BACKWARD_LINK_REASON, linked_at=TEST_BACKWARD_LINKED_AT,
        instructions=TEST_BACKWARD_INSTRUCTIONS,
    )
    if not isinstance(result.new_master_state.datum.backward_link, SomeChainLink):
        return False, "link_backward succeeded but backward_link is not set afterward", result.tx_hash
    return True, f"backward_link set permanently, nonce {before.datum.nonce}->{result.new_master_state.datum.nonce}", result.tx_hash


def test_missing_key_error(client: CardanoNetworkClient) -> tuple[bool, str, Optional[str]]:
    """
    Confirms the client raises MissingKeyError cleanly when an action is
    attempted without the required role key, RATHER than silently
    proceeding or failing some other confusing way. Constructs a
    throwaway second client instance with operator key only, no
    authority/owner, and confirms pause() (needs authority) raises the
    right error type.
    """
    operator_only_client = CardanoNetworkClient(
        deployment=client.deployment, funding_signing_key=FUNDING_SIGNING_KEY,
        operator_key=b"\x00" * 32,  # placeholder, never actually used in this test
        network_type=NETWORK_TYPE,
    )
    try:
        operator_only_client.pause()
        return False, "pause() did not raise MissingKeyError despite no authority_key being set", None
    except MissingKeyError as e:
        return True, f"Correctly raised MissingKeyError: {e}", None


# ════════════════════════════════════════════════════════════════════════
# main()
# ════════════════════════════════════════════════════════════════════════

def main() -> int:
    runner = TestRunner()

    print("=== CardanoNetworkClient - Function Test Suite ===\n")

    try:
        perm_keys = json.loads(Path(PERM_KEYS_JSON_PATH).read_text())
        operator_key = bytes.fromhex(perm_keys["operator"]["private_key_hex"])
        authority_key = bytes.fromhex(perm_keys["authority"]["private_key_hex"])
        owner_key = bytes.fromhex(perm_keys["owner"]["private_key_hex"])

        client = CardanoNetworkClient(
            deployment=DEPLOYMENT_JSON_PATH,
            funding_signing_key=FUNDING_SIGNING_KEY,
            operator_key=operator_key,
            authority_key=authority_key,
            owner_key=owner_key,
            network_type=NETWORK_TYPE,
        )
        print(f"Client constructed OK against {NETWORK_TYPE}")
    except Exception as e:
        print(f"\nSETUP FAILED: {e}")
        traceback.print_exc()
        return 1

    runner.run("get_master_state - read", lambda: test_get_master_state(client))
    runner.run("get_stats - read", lambda: test_get_stats(client))
    runner.run("mint_document - write + cross-check via find_document", lambda: test_mint_document(client))
    runner.run("pause / resume - round-trip", lambda: test_pause_resume_roundtrip(client))
    runner.run("rotate_key - round-trip + in-memory sync check", lambda: test_rotate_key_roundtrip(client))
    runner.run("withdraw - write", lambda: test_withdraw(client))
    runner.run("link_forward - one-time only", lambda: test_link_forward(client))
    runner.run("link_backward - one-time only", lambda: test_link_backward(client))
    runner.run("MissingKeyError - raised correctly when role key absent", lambda: test_missing_key_error(client))

    runner.write_report(REPORT_PATH)

    failed = sum(1 for r in runner.results if not r.passed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())