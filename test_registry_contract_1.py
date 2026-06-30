"""
test_registry_contract.py

Real, on-chain integration test suite for archive_registry.ak, run against
a live Yaci DevKit devnet. Every test in this file builds, signs, evaluates,
and submits a REAL transaction - there is no mocking and no tautological
re-implementation of validator logic. A test passes only because the actual
compiled Plutus script, executed by the real node, returned True (for
happy-path tests) or rejected the transaction (for failure-path tests).

PREREQUISITES:
  - Devnet running (yaci-devkit up --enable-yaci-store)
  - A deployment.json (from CardanoDeployer) copied into this same directory,
    describing a LIVE, already-bootstrapped registry deployment
  - perm_keys.json copied into this same directory (same one used at
    deployment time - the test suite needs the PRIVATE halves to actually
    sign transactions, unlike the deployer which only needed public halves)

WHAT THIS SCRIPT DOES NOT DO:
  - It does not run genesis bootstrap. It continues off whatever Master
    UTXO already exists on-chain for the deployment described in
    deployment.json. The registry contract's logic doesn't care how that
    UTXO came to exist - only that it currently exists with a valid beacon
    and datum.
  - It does not trust deployment.json's snapshot values for anything that
    can change over time (nonce, is_paused, key fields). Those are always
    read fresh from the live on-chain datum at the start of the run, using
    the exact same beacon-based discovery mechanism the contract itself
    uses (find_master_output_by_beacon's off-chain equivalent).

OUTPUT:
  - Live progress printed to terminal as each test runs
  - A full text report written to test_report.txt (same directory as this
    script) at the end of the run, regardless of how many tests failed
"""

from __future__ import annotations

import sys
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from pycardano import (
    Address, Asset, AssetName, ExecutionUnits, MultiAsset,
    Network, PaymentExtendedSigningKey, PaymentVerificationKey,
    PlutusV3Script, Redeemer, ScriptHash, StakeExtendedSigningKey,
    StakeVerificationKey, TransactionBuilder, TransactionId, TransactionInput,
    TransactionOutput, UTxO, Value, HDWallet,
)
from pycardano.backend.base import ChainContext

from CardanoDeployer.cardano_network import YaciDevNetApi, NetworkError, UtxoInfo
from CardanoDeployer.cardano_types import (
    AikenFalse, AikenTrue, MasterDatum,
    PlutusAddress, SomeStakeCredential, VerificationKeyCredential,
    OutputReference,
)
from test_types import (
    TokenDatum, AuthorityKeyTag, OperatorKeyTag, OwnerKeyTag,
    MintDocument, Pause, Resume, Withdraw, RotateKey, LinkForward,
    LinkBackward, MintToken, BurnToken,
)
from CardanoDeployer.cardano_workflow import Wallet, PermKeys, GenesisTransaction


# ════════════════════════════════════════════════════════════════════════
# CONFIG
# ════════════════════════════════════════════════════════════════════════

DEPLOYMENT_JSON_PATH = "deployment.json"
PERM_KEYS_JSON_PATH = "perm_keys.json"
PROVIDER_URL = "http://localhost:8080"
REPORT_PATH = "test_report.txt"
NETWORK = Network.TESTNET
TTL_BUFFER_SLOTS = 200

# Test document payload constants - arbitrary but fixed, so tests are
# reproducible and their expected effects are easy to reason about.
TEST_GLOBAL_ID = b"01968f3a-test-cross-chain-id-0001"
TEST_SHA256 = bytes.fromhex("a" * 64)  # 32 bytes, placeholder digest shape
TEST_UPLOAD_DATE = b"2026-06-22T00:00:00Z"
TEST_TOKEN_DATA = b'{"title": "Test Document", "format": "pdf"}'


# ════════════════════════════════════════════════════════════════════════
# Test framework
# ════════════════════════════════════════════════════════════════════════

@dataclass
class TestResult:
    name: str
    passed: bool
    expected_outcome: str          # "should succeed" / "should be rejected"
    detail: str = ""
    tx_id: Optional[str] = None
    duration_seconds: float = 0.0
    exception_text: Optional[str] = None


@dataclass
class TestRunner:
    """
    Owns the running list of results, terminal progress printing, and
    final report writing. Not a generic framework - just enough structure
    for this one suite.
    """
    results: list[TestResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def run(
        self,
        name: str,
        expect_success: bool,
        fn: Callable[[], tuple[bool, str, Optional[str]]],
    ) -> TestResult:
        """
        fn must return (succeeded, detail, tx_id_or_None). fn itself is
        responsible for deciding what "succeeded" means for that specific
        test (e.g. for a failure-path test, fn returns succeeded=True if
        the chain correctly REJECTED the transaction).
        """
        print(f"\n{'─'*70}")
        print(f"TEST: {name}")
        print(f"  expected: {'SUCCESS' if expect_success else 'REJECTION'}")
        sys.stdout.flush()

        start = time.monotonic()
        exc_text = None
        try:
            succeeded, detail, tx_id = fn()
        except Exception as e:
            succeeded = False
            detail = f"Unhandled exception in test body: {e}"
            tx_id = None
            exc_text = traceback.format_exc()
        duration = time.monotonic() - start

        result = TestResult(
            name=name,
            passed=succeeded,
            expected_outcome="should succeed" if expect_success else "should be rejected",
            detail=detail,
            tx_id=tx_id,
            duration_seconds=duration,
            exception_text=exc_text,
        )
        self.results.append(result)

        status = "PASS" if succeeded else "FAIL"
        print(f"  [{status}]  ({duration:.2f}s)")
        if tx_id:
            print(f"  tx: {tx_id}")
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

        lines = []
        lines.append("=" * 78)
        lines.append("ZPEPG ARCHIVE REGISTRY - ON-CHAIN INTEGRATION TEST REPORT")
        lines.append("=" * 78)
        lines.append(f"Started:  {self.started_at.isoformat()}")
        lines.append(f"Finished: {ended_at.isoformat()}")
        lines.append(f"Total duration: {(ended_at - self.started_at).total_seconds():.2f}s")
        lines.append("")
        lines.append(f"TOTAL: {total}   PASSED: {passed}   FAILED: {failed}")
        lines.append("=" * 78)
        lines.append("")

        for i, r in enumerate(self.results, 1):
            lines.append(f"[{i}/{total}] {'PASS' if r.passed else 'FAIL'}  {r.name}")
            lines.append(f"    expected:  {r.expected_outcome}")
            lines.append(f"    duration:  {r.duration_seconds:.2f}s")
            if r.tx_id:
                lines.append(f"    tx_id:     {r.tx_id}")
            lines.append(f"    detail:    {r.detail}")
            if r.exception_text:
                lines.append("    exception:")
                for line in r.exception_text.splitlines():
                    lines.append(f"      {line}")
            lines.append("")

        lines.append("=" * 78)
        lines.append("SUMMARY")
        lines.append("=" * 78)
        for r in self.results:
            lines.append(f"  {'PASS' if r.passed else 'FAIL'}  {r.name}")

        Path(path).write_text("\n".join(lines))
        print(f"\nReport written to: {path}")
        print(f"TOTAL: {total}   PASSED: {passed}   FAILED: {failed}")


# ════════════════════════════════════════════════════════════════════════
# Minimal ChainContext (same pattern as GenesisTransaction._ProviderContext)
# ════════════════════════════════════════════════════════════════════════

class _ProviderContext(ChainContext):
    """
    Mirrors GenesisTransaction._ProviderContext exactly - implements only
    what TransactionBuilder actually calls. Re-declared here rather than
    imported because it's a private nested class of GenesisTransaction;
    duplicating ~25 lines is cheaper than changing that class's visibility
    just for test code.
    """

    def __init__(self, backend: YaciDevNetApi, network: Network):
        self._backend = backend
        self._network = network
        self._cached_params = None

    @property
    def network(self) -> Network:
        return self._network

    @property
    def protocol_param(self):
        if self._cached_params is None:
            self._cached_params = self._backend.protocol_parameters()
        return self._cached_params

    @property
    def last_block_slot(self) -> int:
        return self._backend.current_slot()

    def utxos(self, address) -> list[UTxO]:
        addr_str = str(address)
        provider_utxos = self._backend.get_utxos(addr_str)
        results = []
        POLICY_ID_HEX_LEN = 56
        for u in provider_utxos:
            tx_input = TransactionInput(
                transaction_id=TransactionId(bytes.fromhex(u.tx_hash)),
                index=u.output_index,
            )
            multi_asset = MultiAsset({})
            if u.assets:
                grouped: dict[bytes, dict[bytes, int]] = {}
                for asset in u.assets:
                    policy_hex = asset.unit[:POLICY_ID_HEX_LEN]
                    name_hex = asset.unit[POLICY_ID_HEX_LEN:]
                    p = bytes.fromhex(policy_hex)
                    n = bytes.fromhex(name_hex) if name_hex else b""
                    grouped.setdefault(p, {})[n] = asset.quantity
                multi_asset = MultiAsset({
                    ScriptHash(p): Asset({AssetName(n): q for n, q in names.items()})
                    for p, names in grouped.items()
                })
            tx_output = TransactionOutput(
                address=Address.from_primitive(u.address),
                amount=Value(coin=u.lovelace, multi_asset=multi_asset),
            )
            results.append(UTxO(input=tx_input, output=tx_output))
        return results

    def evaluate_tx_cbor(self, cbor) -> dict[str, ExecutionUnits]:
        cbor_bytes = bytes.fromhex(cbor) if isinstance(cbor, str) else cbor
        return self._backend.evaluate_tx(cbor_bytes)

    def submit_tx_cbor(self, cbor) -> None:
        cbor_bytes = bytes.fromhex(cbor) if isinstance(cbor, str) else cbor
        self._backend.submit_tx(cbor_bytes)


# ════════════════════════════════════════════════════════════════════════
# Live deployment state
# ════════════════════════════════════════════════════════════════════════

@dataclass
class LiveMasterState:
    """
    The CURRENT, real, on-chain state of the Master UTXO - never trusted
    from deployment.json's snapshot, always re-read fresh from chain via
    the same beacon-based discovery the contract itself uses.
    """
    utxo: UTxO
    datum: MasterDatum
    registry_policy_id: bytes
    registry_script_address: Address
    beacon_policy_id: bytes
    beacon_asset_name: bytes


def find_master_utxo_by_beacon(
    backend: YaciDevNetApi,
    registry_script_address: str,
    beacon_policy_id_hex: str,
    beacon_asset_name_hex: str,
) -> UtxoInfo:
    """
    Off-chain equivalent of find_master_output_by_beacon in the Aiken
    contract: scans UTXOs at the registry script address and returns
    whichever one actually holds the beacon token, rather than assuming
    "the only UTXO there" or "the one from deployment.json" is current.
    """
    beacon_unit = beacon_policy_id_hex + beacon_asset_name_hex
    candidates = backend.get_utxos(registry_script_address)
    for u in candidates:
        for a in u.assets:
            if a.unit == beacon_unit and a.quantity == 1:
                return u
    raise RuntimeError(
        f"No UTXO at {registry_script_address} currently holds beacon "
        f"{beacon_unit}. Has genesis bootstrap actually run? Is the "
        f"devnet state what you expect?"
    )


def decode_master_datum(raw_cbor_hex: str) -> MasterDatum:
    return MasterDatum.from_cbor(bytes.fromhex(raw_cbor_hex))


def load_live_master_state(
    backend: YaciDevNetApi,
    deployment: dict,
) -> LiveMasterState:
    registry_script_address = deployment["registry_contract"]["script_address"]
    registry_policy_id_hex = deployment["registry_contract"]["policy_id"]
    beacon_policy_id_hex = deployment["beacon_contract"]["policy_id"]
    beacon_asset_name_hex = deployment["beacon_contract"]["asset_name_hex"]

    utxo_info = find_master_utxo_by_beacon(
        backend, registry_script_address, beacon_policy_id_hex, beacon_asset_name_hex
    )

    # Fetch the raw inline datum CBOR directly - YaciDevNetApi.get_utxos()
    # (via UtxoInfo) doesn't currently surface datum content, only
    # tx_hash/output_index/address/amount. Fetch it directly via the same
    # endpoint already confirmed working.
    import requests
    resp = requests.get(f"{backend.base_url}/api/v1/addresses/{registry_script_address}/utxos")
    resp.raise_for_status()
    raw_items = resp.json()
    matching = next(
        (item for item in raw_items
         if item["tx_hash"] == utxo_info.tx_hash and item["output_index"] == utxo_info.output_index),
        None,
    )
    if matching is None or not matching.get("inline_datum"):
        raise RuntimeError(
            f"Found master UTXO {utxo_info.ref_str} but it has no inline_datum. "
            f"Something is very wrong - the contract requires InlineDatum everywhere."
        )

    datum = decode_master_datum(matching["inline_datum"])

    tx_input = TransactionInput(
        transaction_id=TransactionId(bytes.fromhex(utxo_info.tx_hash)),
        index=utxo_info.output_index,
    )
    multi_asset = MultiAsset({
        ScriptHash(bytes.fromhex(beacon_policy_id_hex)):
            Asset({AssetName(bytes.fromhex(beacon_asset_name_hex)): 1})
    })
    tx_output = TransactionOutput(
        address=Address.from_primitive(registry_script_address),
        amount=Value(coin=utxo_info.lovelace, multi_asset=multi_asset),
        datum=datum,
    )

    return LiveMasterState(
        utxo=UTxO(input=tx_input, output=tx_output),
        datum=datum,
        registry_policy_id=bytes.fromhex(registry_policy_id_hex),
        registry_script_address=Address.from_primitive(registry_script_address),
        beacon_policy_id=bytes.fromhex(beacon_policy_id_hex),
        beacon_asset_name=bytes.fromhex(beacon_asset_name_hex),
    )


# ════════════════════════════════════════════════════════════════════════
# Signing perm keys (PRIVATE halves)
# ════════════════════════════════════════════════════════════════════════
#
# PermKeys.load() in cardano_workflow.py deliberately discards private key
# material - correct for the deployer, which only ever needs to bake PUBLIC
# keys into MasterDatum. This test suite is different: it must actually
# PRODUCE valid signatures as the authority/operator/owner roles, which
# requires the private halves. This loader is intentionally separate from
# PermKeys rather than modifying it, so the deployer's "never persists
# private key material" guarantee is untouched.

@dataclass(frozen=True)
class SigningKeySet:
    authority_private: bytes
    authority_public: bytes
    operator_private: bytes
    operator_public: bytes
    owner_private: bytes
    owner_public: bytes


def load_signing_keys(path: str) -> SigningKeySet:
    import json as _json
    data = _json.loads(Path(path).read_text())
    roles = {}
    for role in ("authority", "operator", "owner"):
        priv = bytes.fromhex(data[role]["private_key_hex"])
        pub = bytes.fromhex(data[role]["public_key_hex"])
        if len(priv) != 32 or len(pub) != 32:
            raise ValueError(f"{role} keys must be 32 bytes each")
        roles[role] = (priv, pub)
    return SigningKeySet(
        authority_private=roles["authority"][0],
        authority_public=roles["authority"][1],
        operator_private=roles["operator"][0],
        operator_public=roles["operator"][1],
        owner_private=roles["owner"][0],
        owner_public=roles["owner"][1],
    )


def sign_ed25519(private_key_32: bytes, message: bytes) -> bytes:
    """
    Raw Ed25519 signing, matching exactly what verify_ed25519_signature
    expects on-chain: a signature over the raw message bytes the contract
    constructs internally (nonce + action-specific fields concatenated via
    bytearray.concat), using a plain 32-byte Ed25519 seed - NOT the
    BIP32-Ed25519 extended-key scheme used for the funding wallet. These
    are bare keypairs per PermKeys' own docstring, so plain nacl signing
    is correct here, deliberately different from PaymentExtendedSigningKey.
    """
    from nacl.signing import SigningKey
    sk = SigningKey(private_key_32)
    signed = sk.sign(message)
    return signed.signature


def int_to_be_bytes(value: int, length: int) -> bytes:
    """Matches Aiken's bytearray.from_int_big_endian(value, length) exactly."""
    return value.to_bytes(length, byteorder="big", signed=False)


# ════════════════════════════════════════════════════════════════════════
# Generic master-UTXO spend transaction builder
# ════════════════════════════════════════════════════════════════════════

def build_master_spend_tx(
    context: _ProviderContext,
    funding_account: "Wallet.DerivedAccount",
    master: LiveMasterState,
    registry_script: PlutusV3Script,
    redeemer_data,
    new_datum: MasterDatum,
    extra_outputs: Optional[list[TransactionOutput]] = None,
):
    """
    Builds (does not submit) a transaction that spends the current master
    UTXO with the given RegistryAction redeemer, producing a successor
    master UTXO carrying the beacon forward with new_datum. Any
    extra_outputs (e.g. a freshly minted document token, or a withdrawal
    payment) are appended after the master output.

    No reference script exists for archive_registry in this deployment
    (genesis bootstrap never created one - it only ever attached the
    beacon script directly for the one-time mint). So registry_script's
    full compiled bytecode is attached directly to every spending
    transaction here, same direct-attachment pattern already proven
    working for the beacon script.

    Returns the unsigned-but-built TransactionBuilder so callers can
    inspect/mutate before signing, or just call .build_and_sign().
    """
    beacon_multi_asset = MultiAsset({
        ScriptHash(master.beacon_policy_id):
            Asset({AssetName(master.beacon_asset_name): 1})
    })

    builder = TransactionBuilder(context, ttl=context.last_block_slot + TTL_BUFFER_SLOTS)
    builder.add_input_address(funding_account.address)
    builder.add_script_input(
        utxo=master.utxo,
        script=registry_script,
        redeemer=Redeemer(redeemer_data),
    )
    builder.add_output(TransactionOutput(
        address=master.registry_script_address,
        amount=Value(coin=master.utxo.output.amount.coin, multi_asset=beacon_multi_asset),
        datum=new_datum,
    ))
    for out in (extra_outputs or []):
        builder.add_output(out)

    return builder


def fund_and_sign(
    builder: TransactionBuilder,
    funding_account: "Wallet.DerivedAccount",
    extra_signing_keys: Optional[list] = None,
):
    signing_keys = [funding_account.payment_signing_key] + (extra_signing_keys or [])
    return builder.build_and_sign(
        signing_keys=signing_keys,
        change_address=funding_account.address,
    )


# ════════════════════════════════════════════════════════════════════════
# Setup
# ════════════════════════════════════════════════════════════════════════

@dataclass
class Suite:
    """Bag of everything every test needs. Built once in main(), passed around."""
    context: _ProviderContext
    backend: YaciDevNetApi
    deployment: dict
    funding_account: "Wallet.DerivedAccount"
    signing_keys: SigningKeySet
    registry_script: PlutusV3Script
    master: LiveMasterState  # refreshed via refresh_master() after each test


def refresh_master(suite: "Suite", expected_nonce: Optional[int] = None, timeout_s: float = 15.0, poll_interval_s: float = 1.0) -> None:
    """
    Re-fetches the live master UTXO/datum from chain. MUST be called after
    every successful state-changing test, since the master UTXO's
    reference and datum both change with every spend. Failure-path tests
    that are correctly rejected do NOT change on-chain state, so no
    refresh is needed after those (though calling it anyway is harmless).

    If expected_nonce is given, polls until the live datum's nonce reaches
    it (or timeout_s elapses) rather than reading immediately - devnet
    block production isn't instant, so an immediate single read can still
    observe the pre-transaction state.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        suite.master = load_live_master_state(suite.backend, suite.deployment)
        if expected_nonce is None or suite.master.datum.nonce == expected_nonce:
            return
        if time.monotonic() >= deadline:
            return  # let the caller's own assertion report the mismatch
        time.sleep(poll_interval_s)


def setup() -> Suite:
    import json as _json

    deployment = _json.loads(Path(DEPLOYMENT_JSON_PATH).read_text())
    signing_keys = load_signing_keys(PERM_KEYS_JSON_PATH)
    backend = YaciDevNetApi(PROVIDER_URL)
    context = _ProviderContext(backend, NETWORK)

    print("--- Resolving funding wallet ---")
    mnemonic_env = __import__("os").environ.get("ZPEPG_MNEMONIC", "").strip()
    if not mnemonic_env:
        import getpass
        mnemonic_env = getpass.getpass("Mnemonic (hidden): ").strip()
    funding_account = Wallet.resolve(
        mnemonic_env,
        deployment["deployed_from_wallet_address"],
        NETWORK,
    )
    print(f"  Resolved: account {funding_account.account_index}, {funding_account.address}")

    print("--- Loading registry validator bytecode ---")
    blueprint_path = deployment["registry_contract"]["bootstrap_generated_plutus_path"]
    blueprint = _json.loads(Path(blueprint_path).read_text())
    registry_title = "registry_contract.archive_registry.spend"
    validator = next(
        (v for v in blueprint["validators"] if v["title"] == registry_title), None
    )
    if validator is None:
        raise RuntimeError(f"'{registry_title}' not found in {blueprint_path}")
    registry_script = PlutusV3Script(bytes.fromhex(validator["compiledCode"]))
    print(f"  Loaded, hash={validator['hash']}")

    print("--- Fetching live master UTXO state ---")
    master = load_live_master_state(backend, deployment)
    print(f"  Master UTXO: {master.utxo.input}")
    print(f"  Current nonce: {master.datum.nonce}")
    print(f"  is_paused: {master.datum.is_paused}")

    return Suite(
        context=context,
        backend=backend,
        deployment=deployment,
        funding_account=funding_account,
        signing_keys=signing_keys,
        registry_script=registry_script,
        master=master,
    )


# ════════════════════════════════════════════════════════════════════════
# Happy-path tests
# ════════════════════════════════════════════════════════════════════════

def test_mint_document(suite: Suite) -> tuple[bool, str, Optional[str]]:
    """
    Exercises MintDocument: signs with operator_key, builds the
    accompanying TokenDatum + minted token output, and submits. Tests the
    spend branch's full check list (signature, nonce, beacon carried
    forward, token datum cross-validation, stats update) AND the mint
    branch's checks (asset name prefix, beacon presence on the spent
    master input) in one real transaction, since both validators run
    together exactly as they would in production use.
    """
    old_datum = suite.master.datum
    nonce = old_datum.nonce
    version = 1
    is_unique = True
    expected_unique_inc = 1 if is_unique else 0

    signed_payload = (
        int_to_be_bytes(nonce, 8)
        + TEST_GLOBAL_ID
        + TEST_SHA256
        + int_to_be_bytes(version, 4)
    )
    signature = sign_ed25519(suite.signing_keys.operator_private, signed_payload)

    redeemer = MintDocument(
        nonce=nonce,
        cross_chain_global_id=TEST_GLOBAL_ID,
        sha256_hash=TEST_SHA256,
        upload_date=TEST_UPLOAD_DATE,
        version=version,
        token_data=TEST_TOKEN_DATA,
        is_unique_document=AikenTrue() if is_unique else AikenFalse(),
        valid_lower_bound=nonce,  # arbitrary fixed marker, just needs to match new_datum check
        signature=signature,
    )

    asset_name_prefix = old_datum.asset_name_prefix
    asset_name = asset_name_prefix + int_to_be_bytes(nonce, 4)  # unique-ish per run
    token_id = suite.master.registry_policy_id + asset_name

    new_datum = MasterDatum(
        authority_key=old_datum.authority_key,
        operator_key=old_datum.operator_key,
        owner_key=old_datum.owner_key,
        owner_address=old_datum.owner_address,
        nonce=nonce + 1,
        is_paused=old_datum.is_paused,
        policy_id=old_datum.policy_id,
        asset_name_prefix=old_datum.asset_name_prefix,
        beacon_policy_id=old_datum.beacon_policy_id,
        beacon_asset_name=old_datum.beacon_asset_name,
        forward_link=old_datum.forward_link,
        backward_link=old_datum.backward_link,
        stats=type(old_datum.stats)(
            total_token_count=old_datum.stats.total_token_count + 1,
            total_unique_documents=old_datum.stats.total_unique_documents + expected_unique_inc,
            last_minted_at=nonce,  # matches valid_lower_bound above
            last_cross_chain_global_id=TEST_GLOBAL_ID,
            last_cardano_asset_id=token_id,  # computed above, no post-construction mutation needed
        ),
    )

    token_datum = TokenDatum(
        cardano_asset_id=token_id,
        cross_chain_global_id=TEST_GLOBAL_ID,
        registry_address=b"",
        policy_id=suite.master.registry_policy_id,
        source_registry_master_utxo_reference=OutputReference(
            transaction_id=suite.master.utxo.input.transaction_id.payload,
            output_index=suite.master.utxo.input.index,
        ),
        sha256_hash=TEST_SHA256,
        upload_date=TEST_UPLOAD_DATE,
        version=version,
        token_data=TEST_TOKEN_DATA,
    )

    token_multi_asset = MultiAsset({
        ScriptHash(suite.master.registry_policy_id): Asset({AssetName(asset_name): 1})
    })
    token_output = TransactionOutput(
        address=suite.funding_account.address,  # destination is caller-specified per the design doc
        amount=Value(coin=3_000_000, multi_asset=token_multi_asset),
        datum=token_datum,
    )

    builder = build_master_spend_tx(
        suite.context, suite.funding_account, suite.master,
        suite.registry_script, redeemer, new_datum,
        extra_outputs=[token_output],
    )
    builder.add_minting_script(suite.registry_script, Redeemer(MintToken()))
    builder.mint = token_multi_asset

    try:
        signed_tx = fund_and_sign(builder, suite.funding_account)
        suite.context.submit_tx(signed_tx)
    except Exception as e:
        return False, f"Transaction failed unexpectedly: {e}", None

    refresh_master(suite, expected_nonce=nonce + 1)
    if suite.master.datum.nonce != nonce + 1:
        return False, f"Nonce after mint is {suite.master.datum.nonce}, expected {nonce + 1}", str(signed_tx.id)
    if suite.master.datum.stats.total_token_count != old_datum.stats.total_token_count + 1:
        return False, "total_token_count did not increment correctly", str(signed_tx.id)

    return True, (
        f"Minted document, nonce {nonce}->{nonce+1}, "
        f"total_token_count={suite.master.datum.stats.total_token_count}"
    ), str(signed_tx.id)


# ════════════════════════════════════════════════════════════════════════
# main() - currently runs ONLY MintDocument, deliberately, to verify the
# test harness itself before building more tests on top of it.
# ════════════════════════════════════════════════════════════════════════

def main() -> int:
    runner = TestRunner()

    print("=== ZPEPG archive_registry.ak - Real On-Chain Test Suite ===")
    print(f"(stage: harness verification - MintDocument only)\n")

    try:
        suite = setup()
    except Exception as e:
        print(f"\nSETUP FAILED: {e}")
        traceback.print_exc()
        return 1

    runner.run(
        name="MintDocument - happy path",
        expect_success=True,
        fn=lambda: test_mint_document(suite),
    )

    runner.write_report(REPORT_PATH)

    failed = sum(1 for r in runner.results if not r.passed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())