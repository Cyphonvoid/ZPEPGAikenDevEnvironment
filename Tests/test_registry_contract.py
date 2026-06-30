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
    OutputReference, DeploymentChainLink, SomeChainLink, NoneChainLink,
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
TTL_BUFFER_SLOTS = 800

# Test document payload constants - arbitrary but fixed, so tests are
# reproducible and their expected effects are easy to reason about.
TEST_GLOBAL_ID = b"01968f3a-test-cross-chain-id-0001"
TEST_SHA256 = bytes.fromhex("a" * 64)  # 32 bytes, placeholder digest shape
TEST_UPLOAD_DATE = b"2026-06-22T00:00:00Z"
TEST_TOKEN_DATA = b'{"title": "Test Document", "format": "pdf"}'

# Link-test constants. The contract never verifies these resolve to a real
# deployed script anywhere (see design discussion: next_script_address /
# next_policy_id are plain ByteArray pointers, not verified Address/
# Credential types) - so any correctly-shaped bytes are valid here.
TEST_FORWARD_SCRIPT_ADDRESS = bytes.fromhex("11" * 28)
TEST_FORWARD_POLICY_ID = bytes.fromhex("22" * 28)
TEST_FORWARD_LINK_REASON = b"test-forward-migration"
TEST_FORWARD_LINKED_AT = 1_900_000_000
TEST_FORWARD_INSTRUCTIONS = b'{"note": "test forward link, not a real deployment"}'

TEST_BACKWARD_SCRIPT_ADDRESS = bytes.fromhex("33" * 28)
TEST_BACKWARD_POLICY_ID = bytes.fromhex("44" * 28)
TEST_BACKWARD_LINK_REASON = b"test-backward-migration"
TEST_BACKWARD_LINKED_AT = 1_800_000_000
TEST_BACKWARD_INSTRUCTIONS = b'{"note": "test backward link, not a real deployment"}'

TEST_WITHDRAW_AMOUNT = 2_000_000  # 2 ADA, comfortably above min-UTxO for a plain-ADA output


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
    registry_script_address = deployment["contract"]["script_address"]
    registry_policy_id_hex = deployment["contract"]["policy_id"]
    # Single-script architecture: beacon's policy ID is now IDENTICAL to
    # the registry's own policy ID (same compiled script, same hash) -
    # deployment.json's "beacon" section no longer has its own policy_id
    # field at all, by design (see cardano_workflow.py's DeploymentRecord
    # docstring). Only asset_name still varies independently.
    beacon_policy_id_hex = registry_policy_id_hex
    beacon_asset_name_hex = deployment["beacon"]["asset_name_hex"]

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

    # Master output's lovelace can't simply be carried forward unchanged:
    # min-UTxO scales with output size (assets + inline datum bytes), and
    # new_datum can be substantially bigger than old_datum was (e.g. once
    # forward_link/backward_link hold a real DeploymentChainLink instead
    # of None). Compute the actual minimum required for THIS output and
    # use whichever is larger - the old flat amount, or the real minimum -
    # so this never silently under-funds as the datum's shape evolves.
    master_output = TransactionOutput(
        address=master.registry_script_address,
        amount=Value(coin=master.utxo.output.amount.coin, multi_asset=beacon_multi_asset),
        datum=new_datum,
    )
    try:
        from pycardano import min_lovelace_post_alonzo as _min_lovelace
        min_required = _min_lovelace(master_output, context)
    except ImportError:
        from pycardano.utils import min_lovelace_post_alonzo as _min_lovelace
        min_required = _min_lovelace(master_output, context)
    master_coin = max(master.utxo.output.amount.coin, min_required)
    master_output.amount = Value(coin=master_coin, multi_asset=beacon_multi_asset)

    builder = TransactionBuilder(context, ttl=context.last_block_slot + TTL_BUFFER_SLOTS)
    builder.add_input_address(funding_account.address)
    builder.add_script_input(
        utxo=master.utxo,
        script=registry_script,
        redeemer=Redeemer(redeemer_data),
    )
    builder.add_output(master_output)
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
    blueprint_path = deployment["contract"]["bootstrap_generated_plutus_path"]
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
    master input, asset/datum/address co-location) in one real
    transaction, since both validators run together exactly as they
    would in production use.

    The minted document token is sent to the REGISTRY SCRIPT'S OWN
    ADDRESS, not any external wallet. This is a deliberate, permanent
    design choice: document tokens are anti-censorship archive records,
    never wallet-custodied or transferable. Once minted here, they
    become structurally unspendable by anyone, forever - the spend
    validator only ever attempts to decode a spent UTXO's datum as
    MasterDatum, which a TokenDatum-shaped value can never satisfy. There
    is no redeemer, no signature, no future action (not even by
    authority) that can move a document token out of this address. This
    isn't a policy choice enforced by convention - it's a structural
    consequence of the validator's own decode logic, with no escape
    valve anywhere in the design.
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
        address=suite.master.registry_script_address,  # PERMANENT lock - never an external wallet
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


def test_pause(suite: Suite) -> tuple[bool, str, Optional[str]]:
    """
    Exercises Pause: signed with authority_key. Spend-only branch, no
    extra outputs - the master output is the entire transaction's
    business. Confirms is_paused flips False->True and every other
    field is preserved untouched.
    """
    old_datum = suite.master.datum
    nonce = old_datum.nonce

    signed_payload = int_to_be_bytes(nonce, 8) + b"PAUSE"
    signature = sign_ed25519(suite.signing_keys.authority_private, signed_payload)

    redeemer = Pause(nonce=nonce, signature=signature)

    new_datum = MasterDatum(
        authority_key=old_datum.authority_key,
        operator_key=old_datum.operator_key,
        owner_key=old_datum.owner_key,
        owner_address=old_datum.owner_address,
        nonce=nonce + 1,
        is_paused=AikenTrue(),
        policy_id=old_datum.policy_id,
        asset_name_prefix=old_datum.asset_name_prefix,
        forward_link=old_datum.forward_link,
        backward_link=old_datum.backward_link,
        stats=old_datum.stats,
    )

    builder = build_master_spend_tx(
        suite.context, suite.funding_account, suite.master,
        suite.registry_script, redeemer, new_datum,
    )

    try:
        signed_tx = fund_and_sign(builder, suite.funding_account)
        suite.context.submit_tx(signed_tx)
    except Exception as e:
        return False, f"Transaction failed unexpectedly: {e}", None

    refresh_master(suite, expected_nonce=nonce + 1)
    if suite.master.datum.nonce != nonce + 1:
        return False, f"Nonce after pause is {suite.master.datum.nonce}, expected {nonce + 1}", str(signed_tx.id)
    if not isinstance(suite.master.datum.is_paused, AikenTrue):
        return False, f"is_paused after Pause is {suite.master.datum.is_paused}, expected AikenTrue", str(signed_tx.id)

    return True, f"Paused, nonce {nonce}->{nonce+1}, is_paused=True", str(signed_tx.id)


def test_resume(suite: Suite) -> tuple[bool, str, Optional[str]]:
    """
    Exercises Resume: signed with authority_key. Mirror of test_pause,
    flipping is_paused True->False. Run immediately after test_pause so
    the contract isn't left paused for any later test (or later run) that
    needs MintDocument's `is_paused == False` precondition to hold.
    """
    old_datum = suite.master.datum
    nonce = old_datum.nonce

    signed_payload = int_to_be_bytes(nonce, 8) + b"RESUME"
    signature = sign_ed25519(suite.signing_keys.authority_private, signed_payload)

    redeemer = Resume(nonce=nonce, signature=signature)

    new_datum = MasterDatum(
        authority_key=old_datum.authority_key,
        operator_key=old_datum.operator_key,
        owner_key=old_datum.owner_key,
        owner_address=old_datum.owner_address,
        nonce=nonce + 1,
        is_paused=AikenFalse(),
        policy_id=old_datum.policy_id,
        asset_name_prefix=old_datum.asset_name_prefix,
        forward_link=old_datum.forward_link,
        backward_link=old_datum.backward_link,
        stats=old_datum.stats,
    )

    builder = build_master_spend_tx(
        suite.context, suite.funding_account, suite.master,
        suite.registry_script, redeemer, new_datum,
    )

    try:
        signed_tx = fund_and_sign(builder, suite.funding_account)
        suite.context.submit_tx(signed_tx)
    except Exception as e:
        return False, f"Transaction failed unexpectedly: {e}", None

    refresh_master(suite, expected_nonce=nonce + 1)
    if suite.master.datum.nonce != nonce + 1:
        return False, f"Nonce after resume is {suite.master.datum.nonce}, expected {nonce + 1}", str(signed_tx.id)
    if not isinstance(suite.master.datum.is_paused, AikenFalse):
        return False, f"is_paused after Resume is {suite.master.datum.is_paused}, expected AikenFalse", str(signed_tx.id)

    return True, f"Resumed, nonce {nonce}->{nonce+1}, is_paused=False", str(signed_tx.id)


def _rotate_operator_key(suite: Suite, new_operator_pub: bytes) -> tuple[bool, str, Optional[str]]:
    """
    Shared body for one direction of the operator-key rotation. Signed
    with authority_key, since RotateKey is an authority-only action
    regardless of which key_type is being rotated.
    """
    old_datum = suite.master.datum
    nonce = old_datum.nonce

    signed_payload = (
        int_to_be_bytes(nonce, 8) + b"ROTATE" + b"OPERATOR" + new_operator_pub
    )
    signature = sign_ed25519(suite.signing_keys.authority_private, signed_payload)

    redeemer = RotateKey(
        nonce=nonce,
        key_type=OperatorKeyTag(),
        new_key=new_operator_pub,
        signature=signature,
    )

    new_datum = MasterDatum(
        authority_key=old_datum.authority_key,
        operator_key=new_operator_pub,
        owner_key=old_datum.owner_key,
        owner_address=old_datum.owner_address,
        nonce=nonce + 1,
        is_paused=old_datum.is_paused,
        policy_id=old_datum.policy_id,
        asset_name_prefix=old_datum.asset_name_prefix,
        forward_link=old_datum.forward_link,
        backward_link=old_datum.backward_link,
        stats=old_datum.stats,
    )

    builder = build_master_spend_tx(
        suite.context, suite.funding_account, suite.master,
        suite.registry_script, redeemer, new_datum,
    )

    try:
        signed_tx = fund_and_sign(builder, suite.funding_account)
        suite.context.submit_tx(signed_tx)
    except Exception as e:
        return False, f"Transaction failed unexpectedly: {e}", None

    refresh_master(suite, expected_nonce=nonce + 1)
    if suite.master.datum.nonce != nonce + 1:
        return False, f"Nonce after rotate is {suite.master.datum.nonce}, expected {nonce + 1}", str(signed_tx.id)
    if suite.master.datum.operator_key != new_operator_pub:
        return False, "operator_key did not update to the expected new key", str(signed_tx.id)

    return True, f"Rotated operator_key, nonce {nonce}->{nonce+1}", str(signed_tx.id)


def test_rotate_key_operator_roundtrip(suite: Suite) -> tuple[bool, str, Optional[str]]:
    """
    Exercises RotateKey for the OperatorKey case in both directions in a
    single test: rotate to a freshly generated throwaway keypair, confirm
    it landed, then rotate back to the ORIGINAL operator key from
    perm_keys.json. This keeps the on-chain operator_key consistent with
    perm_keys.json after the test finishes, so later runs (including
    MintDocument, which signs with operator_private from perm_keys.json)
    keep working without needing perm_keys.json regenerated/updated.

    AuthorityKey/OwnerKey rotation aren't covered here (same validator
    logic path, different key_type branch) - operator round-trip alone
    confirms RotateKey's signature/nonce/static-field-preservation checks
    all work correctly on a real on-chain transaction.
    """
    from nacl.signing import SigningKey as _SigningKey

    original_operator_pub = suite.signing_keys.operator_public
    throwaway_signing_key = _SigningKey.generate()
    throwaway_pub = bytes(throwaway_signing_key.verify_key)

    ok, detail, tx_id = _rotate_operator_key(suite, throwaway_pub)
    if not ok:
        return False, f"[rotate to throwaway] {detail}", tx_id

    ok2, detail2, tx_id2 = _rotate_operator_key(suite, original_operator_pub)
    if not ok2:
        return False, (
            f"[rotate to throwaway] succeeded, but [rotate back to original] failed: {detail2}. "
            f"WARNING: on-chain operator_key is now the throwaway key, NOT what's in perm_keys.json "
            f"- subsequent MintDocument runs will fail to sign correctly until this is manually fixed."
        ), tx_id2

    return True, (
        f"Operator key round-trip confirmed: original -> throwaway -> original. "
        f"[{detail}] then [{detail2}]"
    ), tx_id2


def test_link_forward(suite: Suite) -> tuple[bool, str, Optional[str]]:
    """
    Exercises LinkForward: signed with authority_key. PERMANENT, ONE-TIME
    ONLY per live deployment - the contract enforces old_datum.forward_link
    == None as a hard precondition, with no mechanism to reset it. This
    test will correctly FAIL (precondition violated, not a bug) if run a
    second time against the same devnet state without a fresh genesis
    redeploy in between - that's the contract's lockout guard working as
    designed, not a test harness problem.

    next_script_address / next_policy_id are arbitrary test bytes, not a
    real second deployment - the contract has no way to verify these
    resolve to anything real (see ByteArray-vs-Address design discussion),
    so this fully exercises the validator's actual guarantee: a
    permanently locked, signature-authenticated pointer, nothing more.
    """
    old_datum = suite.master.datum
    nonce = old_datum.nonce

    if not isinstance(old_datum.forward_link, NoneChainLink):
        return False, (
            "Precondition failed: forward_link is already set (not None). "
            "LinkForward is a one-time-only action per deployment - redeploy "
            "genesis fresh on devnet to test this again."
        ), None

    signed_payload = (
        int_to_be_bytes(nonce, 8)
        + TEST_FORWARD_POLICY_ID
        + TEST_FORWARD_SCRIPT_ADDRESS
        + TEST_FORWARD_LINK_REASON
    )
    signature = sign_ed25519(suite.signing_keys.authority_private, signed_payload)

    redeemer = LinkForward(
        nonce=nonce,
        next_script_address=TEST_FORWARD_SCRIPT_ADDRESS,
        next_policy_id=TEST_FORWARD_POLICY_ID,
        link_reason=TEST_FORWARD_LINK_REASON,
        linked_at=TEST_FORWARD_LINKED_AT,
        instructions=TEST_FORWARD_INSTRUCTIONS,
        signature=signature,
    )

    chain_link = DeploymentChainLink(
        next_script_address=TEST_FORWARD_SCRIPT_ADDRESS,
        next_policy_id=TEST_FORWARD_POLICY_ID,
        link_reason=TEST_FORWARD_LINK_REASON,
        linked_at=TEST_FORWARD_LINKED_AT,
        instructions=TEST_FORWARD_INSTRUCTIONS,
        current_authority_key=old_datum.authority_key,
        signature=signature,
        nonce_at_link=nonce,
    )

    new_datum = MasterDatum(
        authority_key=old_datum.authority_key,
        operator_key=old_datum.operator_key,
        owner_key=old_datum.owner_key,
        owner_address=old_datum.owner_address,
        nonce=nonce + 1,
        is_paused=old_datum.is_paused,
        policy_id=old_datum.policy_id,
        asset_name_prefix=old_datum.asset_name_prefix,
        forward_link=SomeChainLink(value=chain_link),
        backward_link=old_datum.backward_link,
        stats=old_datum.stats,
    )

    builder = build_master_spend_tx(
        suite.context, suite.funding_account, suite.master,
        suite.registry_script, redeemer, new_datum,
    )

    try:
        signed_tx = fund_and_sign(builder, suite.funding_account)
        suite.context.submit_tx(signed_tx)
    except Exception as e:
        return False, f"Transaction failed unexpectedly: {e}", None

    refresh_master(suite, expected_nonce=nonce + 1)
    if suite.master.datum.nonce != nonce + 1:
        return False, f"Nonce after LinkForward is {suite.master.datum.nonce}, expected {nonce + 1}", str(signed_tx.id)
    if not isinstance(suite.master.datum.forward_link, SomeChainLink):
        return False, "forward_link is not set after LinkForward", str(signed_tx.id)
    linked = suite.master.datum.forward_link.value
    if linked.next_script_address != TEST_FORWARD_SCRIPT_ADDRESS or linked.next_policy_id != TEST_FORWARD_POLICY_ID:
        return False, "forward_link fields don't match what was submitted", str(signed_tx.id)

    return True, f"Linked forward, nonce {nonce}->{nonce+1}, forward_link set permanently", str(signed_tx.id)


def test_link_backward(suite: Suite) -> tuple[bool, str, Optional[str]]:
    """
    Exercises LinkBackward: signed with authority_key. Mirror of
    test_link_forward, writing to backward_link instead - same permanent,
    one-time-only constraint (old_datum.backward_link must be None),
    same caveat about re-running without a fresh devnet redeploy.

    Note the Aiken branch reuses DeploymentChainLink's `next_script_address`
    / `next_policy_id` field names to store what are semantically the
    PREVIOUS deployment's pointers (see registry_contract.ak's LinkBackward
    branch: `expect link.next_script_address == prev_script_address`) -
    that's the contract's own naming choice, not a test-harness mismatch.
    """
    old_datum = suite.master.datum
    nonce = old_datum.nonce

    if not isinstance(old_datum.backward_link, NoneChainLink):
        return False, (
            "Precondition failed: backward_link is already set (not None). "
            "LinkBackward is a one-time-only action per deployment - redeploy "
            "genesis fresh on devnet to test this again."
        ), None

    signed_payload = (
        int_to_be_bytes(nonce, 8)
        + TEST_BACKWARD_POLICY_ID
        + TEST_BACKWARD_SCRIPT_ADDRESS
        + TEST_BACKWARD_LINK_REASON
    )
    signature = sign_ed25519(suite.signing_keys.authority_private, signed_payload)

    redeemer = LinkBackward(
        nonce=nonce,
        prev_script_address=TEST_BACKWARD_SCRIPT_ADDRESS,
        prev_policy_id=TEST_BACKWARD_POLICY_ID,
        link_reason=TEST_BACKWARD_LINK_REASON,
        linked_at=TEST_BACKWARD_LINKED_AT,
        instructions=TEST_BACKWARD_INSTRUCTIONS,
        signature=signature,
    )

    chain_link = DeploymentChainLink(
        next_script_address=TEST_BACKWARD_SCRIPT_ADDRESS,  # semantically "prev" here, per contract's field reuse
        next_policy_id=TEST_BACKWARD_POLICY_ID,
        link_reason=TEST_BACKWARD_LINK_REASON,
        linked_at=TEST_BACKWARD_LINKED_AT,
        instructions=TEST_BACKWARD_INSTRUCTIONS,
        current_authority_key=old_datum.authority_key,
        signature=signature,
        nonce_at_link=nonce,
    )

    new_datum = MasterDatum(
        authority_key=old_datum.authority_key,
        operator_key=old_datum.operator_key,
        owner_key=old_datum.owner_key,
        owner_address=old_datum.owner_address,
        nonce=nonce + 1,
        is_paused=old_datum.is_paused,
        policy_id=old_datum.policy_id,
        asset_name_prefix=old_datum.asset_name_prefix,
        forward_link=old_datum.forward_link,
        backward_link=SomeChainLink(value=chain_link),
        stats=old_datum.stats,
    )

    builder = build_master_spend_tx(
        suite.context, suite.funding_account, suite.master,
        suite.registry_script, redeemer, new_datum,
    )

    try:
        signed_tx = fund_and_sign(builder, suite.funding_account)
        suite.context.submit_tx(signed_tx)
    except Exception as e:
        return False, f"Transaction failed unexpectedly: {e}", None

    refresh_master(suite, expected_nonce=nonce + 1)
    if suite.master.datum.nonce != nonce + 1:
        return False, f"Nonce after LinkBackward is {suite.master.datum.nonce}, expected {nonce + 1}", str(signed_tx.id)
    if not isinstance(suite.master.datum.backward_link, SomeChainLink):
        return False, "backward_link is not set after LinkBackward", str(signed_tx.id)
    linked = suite.master.datum.backward_link.value
    if linked.next_script_address != TEST_BACKWARD_SCRIPT_ADDRESS or linked.next_policy_id != TEST_BACKWARD_POLICY_ID:
        return False, "backward_link fields don't match what was submitted", str(signed_tx.id)

    return True, f"Linked backward, nonce {nonce}->{nonce+1}, backward_link set permanently", str(signed_tx.id)


def test_withdraw(suite: Suite) -> tuple[bool, str, Optional[str]]:
    """
    Exercises Withdraw: signed with owner_key. Requires a SEPARATE
    transaction output paying exactly TEST_WITHDRAW_AMOUNT lovelace to
    old_datum.owner_address (checked via list.any over self.outputs in
    the validator). owner_address was set at genesis bootstrap to the
    funding wallet's own address (confirmed by comparing its decoded
    payment/stake credential hashes against the funding wallet's), so
    suite.funding_account.address is used directly as the payout
    destination - it's the same address, just expressed as a real
    pycardano Address rather than the raw on-chain Plutus Address bytes.

    The master output itself keeps a flat lovelace balance (same pattern
    as every other test here, via build_master_spend_tx) - the withdrawal
    payment's lovelace is sourced from the funding wallet's own UTxOs via
    coin selection, same as transaction fees always are. This is correct
    for exercising the validator's actual on-chain guarantee (a real,
    exact-amount payment to the locked owner_address occurred,
    authenticated by the owner_key signature) even though, unlike a
    production deployment that accumulates real revenue in the master
    UTXO, this devnet master UTXO was never funded with anything to
    "withdraw" from in a literal treasury sense.
    """
    old_datum = suite.master.datum
    nonce = old_datum.nonce
    amount = TEST_WITHDRAW_AMOUNT

    signed_payload = (
        int_to_be_bytes(nonce, 8) + b"WITHDRAW" + int_to_be_bytes(amount, 8)
    )
    signature = sign_ed25519(suite.signing_keys.owner_private, signed_payload)

    redeemer = Withdraw(nonce=nonce, amount=amount, signature=signature)

    new_datum = MasterDatum(
        authority_key=old_datum.authority_key,
        operator_key=old_datum.operator_key,
        owner_key=old_datum.owner_key,
        owner_address=old_datum.owner_address,
        nonce=nonce + 1,
        is_paused=old_datum.is_paused,
        policy_id=old_datum.policy_id,
        asset_name_prefix=old_datum.asset_name_prefix,
        forward_link=old_datum.forward_link,
        backward_link=old_datum.backward_link,
        stats=old_datum.stats,
    )

    withdrawal_output = TransactionOutput(
        address=suite.funding_account.address,
        amount=Value(coin=amount),
    )

    builder = build_master_spend_tx(
        suite.context, suite.funding_account, suite.master,
        suite.registry_script, redeemer, new_datum,
        extra_outputs=[withdrawal_output],
    )

    try:
        signed_tx = fund_and_sign(builder, suite.funding_account)
        suite.context.submit_tx(signed_tx)
    except Exception as e:
        return False, f"Transaction failed unexpectedly: {e}", None

    refresh_master(suite, expected_nonce=nonce + 1)
    if suite.master.datum.nonce != nonce + 1:
        return False, f"Nonce after withdraw is {suite.master.datum.nonce}, expected {nonce + 1}", str(signed_tx.id)

    return True, f"Withdrew {amount} lovelace to owner_address, nonce {nonce}->{nonce+1}", str(signed_tx.id)


def main() -> int:
    runner = TestRunner()

    print("=== ZPEPG archive_registry.ak - Real On-Chain Test Suite ===")
    print(f"(stage: MintDocument, Pause, Resume, RotateKey, LinkForward, LinkBackward, Withdraw)\n")

    try:
        suite = setup()
    except Exception as e:
        print(f"\nSETUP FAILED: {e}")
        traceback.print_exc()
        return 1

    runner.run(
        name="Pause - happy path",
        expect_success=True,
        fn=lambda: test_pause(suite),
    )

    runner.run(
        name="Resume - happy path",
        expect_success=True,
        fn=lambda: test_resume(suite),
    )


    runner.run(
        name="MintDocument - happy path",
        expect_success=True,
        fn=lambda: test_mint_document(suite),
    )



    runner.run(
        name="RotateKey (OperatorKey) - round-trip",
        expect_success=True,
        fn=lambda: test_rotate_key_operator_roundtrip(suite),
    )

    runner.run(
        name="LinkForward - happy path (one-time only)",
        expect_success=True,
        fn=lambda: test_link_forward(suite),
    )

    runner.run(
        name="LinkBackward - happy path (one-time only)",
        expect_success=True,
        fn=lambda: test_link_backward(suite),
    )

    runner.run(
        name="Withdraw - happy path",
        expect_success=True,
        fn=lambda: test_withdraw(suite),
    )


    runner.write_report(REPORT_PATH)
    
    failed = sum(1 for r in runner.results if not r.passed)
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(main())