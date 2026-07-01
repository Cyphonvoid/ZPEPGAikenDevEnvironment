"""
cardano_network_client.py - General-purpose Cardano network client for the
ZPEPG archive_registry contract.

This is a STANDALONE, pluggable client - not coupled to ZPEPG's archive
system, FastAPI backend, or any other infrastructure. It talks to exactly
one thing: a deployed instance of archive_registry (the single-script,
compile-time-parameterized contract - see registry_contract.ak), via
whichever network backend matches the network_type it's constructed with.

DESIGN PRINCIPLES (per project discussion):
  - The user picks a network_type (devnet / testnet / mainnet) and nothing
    else about backend wiring. All provider configuration (URLs, project
    IDs) lives INSIDE the two backend classes below, never exposed to the
    caller.
  - Two backend classes, both real pycardano ChainContext implementations:
      YaciDevnetBackend  - devnet only, wraps the existing, already-proven
                            YaciDevNetApi HTTP logic from cardano_network.py.
      BlockFrostBackend  - testnet (preprod) and mainnet, a thin subclass
                            of pycardano's own BlockFrostChainContext (the
                            official, maintained implementation - no custom
                            low-level evaluation/byte logic is written here
                            at all, deliberately, per project decision to
                            avoid the bug-chasing cost of hand-rolled
                            low-level chain logic).
  - Role keys (authority/operator/owner) are bare Ed25519 keypairs used
    ONLY for on-chain verify_ed25519_signature checks - never used to sign
    the Cardano transaction itself. The funding wallet's signing key is a
    SEPARATE, required input - it pays fees, supplies inputs/collateral,
    and is what actually signs the transaction at the ledger level.
  - Every write method BLOCKS until the transaction is confirmed on-chain
    (polled by the transaction's own locally-computed hash - never opaque
    rescanning) before returning. Cardano's eUTXO model means the entire
    transaction's content (inputs, outputs, datums, hash) is fully known
    locally the moment it's built and signed; confirmation only adds
    whether and where it landed, never new content.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Union

import requests

from pycardano import (
    Address, Asset, AssetName, BlockFrostChainContext, HDWallet, MultiAsset,
    Network, PaymentExtendedSigningKey, PaymentSigningKey,
    PlutusV2Script, PlutusV3Script,
    ProtocolParameters, Redeemer, ScriptHash, StakeExtendedSigningKey,
    TransactionBuilder, TransactionId, TransactionInput, TransactionOutput,
    UTxO, Value,
)
from pycardano.backend.base import ChainContext
from pycardano.plutus import ExecutionUnits
from blockfrost import ApiUrls, ApiError

from CardanoDeployer.cardano_workflow import AikenBlueprint
from CardanoDeployer.cardano_types import (
    AikenFalse, AikenTrue, DeploymentChainLink, MasterDatum, MintBeacon,
    NoneChainLink, OutputReference, PlutusAddress, RegistryStats,
    SomeChainLink, SomeStakeCredential, InlineStakeCredential,
    VerificationKeyCredential,
)
from test_types import (
    TokenDatum, AuthorityKeyTag, OperatorKeyTag, OwnerKeyTag,
    MintDocument, Pause, Resume, Withdraw, RotateKey, LinkForward,
    LinkBackward, MintToken, BurnToken,
)


# ════════════════════════════════════════════════════════════════════════
# Network selector
# ════════════════════════════════════════════════════════════════════════

class CardanoNet(Enum):
    DEVNET = "devnet"
    TESTNET = "testnet"   # maps to Blockfrost preprod internally
    MAINNET = "mainnet"


# ════════════════════════════════════════════════════════════════════════
# Errors
# ════════════════════════════════════════════════════════════════════════

class CardanoNetworkClientError(Exception):
    pass


class MissingKeyError(CardanoNetworkClientError):
    def __init__(self, role: str):
        super().__init__(
            f"This action requires the '{role}' key, but it wasn't provided "
            f"at construction. Pass {role}_key=... when creating CardanoNetworkClient."
        )


class ConfirmationTimeoutError(CardanoNetworkClientError):
    def __init__(self, tx_hash: str, timeout_s: float):
        self.tx_hash = tx_hash
        super().__init__(
            f"Transaction {tx_hash} was submitted but did not confirm within "
            f"{timeout_s}s. It may still confirm later - check tx_hash manually."
        )


# ════════════════════════════════════════════════════════════════════════
# Backend: devnet (Yaci DevKit)
# ════════════════════════════════════════════════════════════════════════

class YaciDevnetBackend(ChainContext):
    """
    Real ChainContext implementation for a local Yaci DevKit devnet.
    Wraps the same proven HTTP logic already confirmed working throughout
    this project's test suites (Ogmios-style evaluate/submit wire formats,
    direct endpoint fetches for UTXOs/protocol-params/tip since pccontext
    has confirmed bugs for all three on this provider).
    """

    DEFAULT_URL = "http://localhost:8080"

    def __init__(self, base_url: str = DEFAULT_URL, network: Network = Network.TESTNET):
        self.base_url = base_url.rstrip("/")
        self._network = network
        self._cached_params: Optional[ProtocolParameters] = None

    # ── internal HTTP helpers ──────────────────────────────────────────

    def _get(self, path: str):
        resp = requests.get(f"{self.base_url}{path}")
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, data: Union[bytes, str], content_type: str) -> requests.Response:
        resp = requests.post(
            f"{self.base_url}{path}", data=data, headers={"Content-Type": content_type}
        )
        if resp.status_code >= 400:
            raise CardanoNetworkClientError(
                f"POST {self.base_url}{path} returned {resp.status_code}: {resp.text}"
            )
        return resp

    # ── ChainContext interface ─────────────────────────────────────────

    @property
    def network(self) -> Network:
        return self._network

    @property
    def protocol_param(self) -> ProtocolParameters:
        if self._cached_params is None:
            p = self._get("/api/v1/epochs/latest/parameters")
            from fractions import Fraction
            self._cached_params = ProtocolParameters(
                min_fee_constant=p["min_fee_b"],
                min_fee_coefficient=p["min_fee_a"],
                max_block_size=p["max_block_size"],
                max_tx_size=p["max_tx_size"],
                max_block_header_size=p["max_block_header_size"],
                key_deposit=int(p["key_deposit"]),
                pool_deposit=int(p["pool_deposit"]),
                pool_influence=Fraction(p["a0"]),
                monetary_expansion=Fraction(p["rho"]),
                treasury_expansion=Fraction(p["tau"]),
                decentralization_param=Fraction(0),
                extra_entropy="",
                protocol_major_version=p["protocol_major_ver"],
                protocol_minor_version=p["protocol_minor_ver"],
                min_utxo=int(p.get("coins_per_utxo_size", 0)),
                min_pool_cost=int(p["min_pool_cost"]),
                price_mem=Fraction(p["price_mem"]),
                price_step=Fraction(p["price_step"]),
                max_tx_ex_mem=int(p["max_tx_ex_mem"]),
                max_tx_ex_steps=int(p["max_tx_ex_steps"]),
                max_block_ex_mem=int(p["max_block_ex_mem"]),
                max_block_ex_steps=int(p["max_block_ex_steps"]),
                max_val_size=int(p["max_val_size"]),
                collateral_percent=p["collateral_percent"],
                max_collateral_inputs=p["max_collateral_inputs"],
                coins_per_utxo_word=int(p.get("coins_per_utxo_size", 0)),
                coins_per_utxo_byte=int(p.get("coins_per_utxo_size", 0)),
                cost_models=p["cost_models"],
                maximum_reference_scripts_size=None,
                min_fee_reference_scripts=None,
            )
        return self._cached_params

    @property
    def last_block_slot(self) -> int:
        return self._get("/api/v1/blocks/latest")["slot"]

    @staticmethod
    def item_to_utxo(item: dict) -> UTxO:
        """
        Converts one raw devnet UTXO JSON item into a pycardano UTxO.
        Deliberately does NOT attach datum (see get_raw_utxos's docstring)
        - callers needing datum content should read item["inline_datum"]
        directly alongside this.
        """
        tx_input = TransactionInput(
            transaction_id=TransactionId(bytes.fromhex(item["tx_hash"])),
            index=item["output_index"],
        )
        lovelace = 0
        POLICY_ID_HEX_LEN = 56
        grouped: dict[bytes, dict[bytes, int]] = {}
        for a in item.get("amount", []):
            if a["unit"] == "lovelace":
                lovelace = int(a["quantity"])
            else:
                p = bytes.fromhex(a["unit"][:POLICY_ID_HEX_LEN])
                n = bytes.fromhex(a["unit"][POLICY_ID_HEX_LEN:])
                grouped.setdefault(p, {})[n] = int(a["quantity"])
        multi_asset = MultiAsset({
            ScriptHash(p): Asset({AssetName(n): q for n, q in names.items()})
            for p, names in grouped.items()
        })
        tx_output = TransactionOutput(
            address=Address.from_primitive(item["address"]),
            amount=Value(coin=lovelace, multi_asset=multi_asset),
        )
        return UTxO(input=tx_input, output=tx_output)

    def utxos(self, address) -> list[UTxO]:
        addr_str = str(address)
        raw = self._get(f"/api/v1/addresses/{addr_str}/utxos")
        results = []
        POLICY_ID_HEX_LEN = 56
        for item in raw:
            tx_input = TransactionInput(
                transaction_id=TransactionId(bytes.fromhex(item["tx_hash"])),
                index=item["output_index"],
            )
            lovelace = 0
            grouped: dict[bytes, dict[bytes, int]] = {}
            for a in item.get("amount", []):
                if a["unit"] == "lovelace":
                    lovelace = int(a["quantity"])
                else:
                    p = bytes.fromhex(a["unit"][:POLICY_ID_HEX_LEN])
                    n = bytes.fromhex(a["unit"][POLICY_ID_HEX_LEN:])
                    grouped.setdefault(p, {})[n] = int(a["quantity"])
            multi_asset = MultiAsset({
                ScriptHash(p): Asset({AssetName(n): q for n, q in names.items()})
                for p, names in grouped.items()
            })
            tx_output = TransactionOutput(
                address=Address.from_primitive(item.get("address", addr_str)),
                amount=Value(coin=lovelace, multi_asset=multi_asset),
            )
            results.append(UTxO(input=tx_input, output=tx_output))
        return results

    def evaluate_tx_cbor(self, cbor) -> dict[str, ExecutionUnits]:
        cbor_bytes = bytes.fromhex(cbor) if isinstance(cbor, str) else cbor
        # Confirmed wire format: hex-encoded CBOR text for evaluate.
        resp = self._post("/api/v1/utils/txs/evaluate", cbor_bytes.hex(), "application/cbor")
        result = resp.json()
        eval_result = result.get("result", {}).get("EvaluationResult")
        if not eval_result:
            raise CardanoNetworkClientError(f"Script evaluation failed: {result}")
        return {
            k: ExecutionUnits(mem=v["memory"], steps=v["steps"])
            for k, v in eval_result.items()
        }

    def submit_tx_cbor(self, cbor) -> None:
        cbor_bytes = bytes.fromhex(cbor) if isinstance(cbor, str) else cbor
        # Confirmed wire format: raw binary CBOR for submit (opposite of evaluate).
        self._post("/api/v1/tx/submit", cbor_bytes, "application/cbor")

    # ── raw UTXO fetch (datum-surfacing workaround) ────────────────────

    def get_raw_utxos(self, address) -> list[dict]:
        """
        Returns the raw JSON items from the devnet's /utxos endpoint,
        including inline_datum hex - which the ChainContext-conforming
        utxos() method above does NOT surface (pycardano's UTxO/Output
        types have no clean way to carry an undecoded datum's raw CBOR
        generically without already knowing its concrete dataclass type).
        Read methods that need datum content use this directly rather
        than guessing at pycardano's internal datum wrapping - same
        proven approach test_registry_contract.py's load_live_master_state
        already uses.
        """
        return self._get(f"/api/v1/addresses/{address}/utxos")

    # ── confirmation lookup (devnet-specific) ──────────────────────────

    def get_tx_status(self, tx_hash: str) -> Optional[dict]:
        """Returns tx info dict if found/confirmed, None if not yet visible."""
        try:
            return self._get(f"/api/v1/txs/{tx_hash}")
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                return None
            raise


# ════════════════════════════════════════════════════════════════════════
# Backend: testnet (preprod) / mainnet (Blockfrost)
# ════════════════════════════════════════════════════════════════════════

class BlockFrostBackend(BlockFrostChainContext):
    """
    Testnet (preprod) and mainnet backend. Directly subclasses pycardano's
    own BlockFrostChainContext - the official, maintained implementation -
    rather than hand-rolling any evaluation/submission/UTXO logic. Project
    IDs are hardcoded here (no env vars, no external config) per project
    decision: this client should be fully self-contained.

    CAVEAT: BLOCKFROST_MAINNET_PROJECT_ID is None until a real mainnet
    Blockfrost project is provisioned - constructing this backend with
    network=MAINNET will raise clearly until that's filled in.
    """

    BLOCKFROST_TESTNET_PROJECT_ID = "preprodviqzO4lW7gcYXeQoxtAg50qneXkq00dW"
    BLOCKFROST_MAINNET_PROJECT_ID = None

    def __init__(self, network: Network):
        if network == Network.TESTNET:
            project_id = self.BLOCKFROST_TESTNET_PROJECT_ID
            base_url = ApiUrls.preprod.value
        elif network == Network.MAINNET:
            if self.BLOCKFROST_MAINNET_PROJECT_ID is None:
                raise CardanoNetworkClientError(
                    "BLOCKFROST_MAINNET_PROJECT_ID is not configured yet in "
                    "BlockFrostBackend. Set it before using network_type=MAINNET."
                )
            project_id = self.BLOCKFROST_MAINNET_PROJECT_ID
            base_url = ApiUrls.mainnet.value
        else:
            raise CardanoNetworkClientError(f"BlockFrostBackend doesn't support network {network}")

        super().__init__(project_id=project_id, network=network, base_url=base_url)
        # Populated by _build_master_spend_tx before each evaluation so
        # evaluate_tx_cbor can pass the script UTxOs as additionalUtxoSet.
        self._script_utxos_for_eval: list = []

    def get_tx_status(self, tx_hash: str) -> Optional[dict]:
        """
        Returns tx info dict if found/confirmed, None if not yet visible.
        VERIFIED: self.api.transaction() returns a blockfrost.utils.Namespace;
        vars(tx) is the correct conversion confirmed against a real transaction.
        """
        try:
            tx = self.api.transaction(hash=tx_hash)
            return vars(tx)
        except ApiError as e:
            if getattr(e, "status_code", None) == 404:
                return None
            raise CardanoNetworkClientError(f"Blockfrost tx status check failed: {e}") from e

    def evaluate_tx_cbor(self, cbor: Union[bytes, str]) -> dict:
        """
        Override to use transaction_evaluate_cbor (direct hex string) rather
        than the base implementation's tempfile-based transaction_evaluate.
        The master UTxO being spent is a real, already-confirmed on-chain
        UTxO, so Blockfrost can resolve it from its own index — no
        additionalUtxoSet needed.
        """
        from pycardano.plutus import ExecutionUnits as _ExecUnits
        from pycardano.exception import TransactionFailedException

        if isinstance(cbor, bytes):
            cbor = cbor.hex()
        result = self.api.transaction_evaluate_cbor(cbor)
        if not hasattr(result, "result"):
            raise TransactionFailedException(result)
        result = result.result
        if not hasattr(result, "EvaluationResult"):
            raise TransactionFailedException(result)
        return {
            k: _ExecUnits(
                getattr(result.EvaluationResult, k).memory,
                getattr(result.EvaluationResult, k).steps,
            )
            for k in vars(result.EvaluationResult)
        }


# ════════════════════════════════════════════════════════════════════════
# Deployment config
# ════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class DeploymentConfig:
    """
    Wraps a deployment.json (single-script architecture shape - see
    cardano_workflow.py's DeploymentRecord). Network client extracts what
    it needs from this; never touches private key material.
    """
    policy_id_hex: str
    script_address: str
    beacon_asset_name_hex: str
    asset_name_prefix_hex: Optional[str]   # not currently in deployment.json - see note below
    bootstrap_generated_plutus_path: str
    raw: dict = field(repr=False)

    @classmethod
    def from_dict(cls, data: dict) -> "DeploymentConfig":
        return cls(
            policy_id_hex=data["contract"]["policy_id"],
            script_address=data["contract"]["script_address"],
            beacon_asset_name_hex=data["beacon"]["asset_name_hex"],
            asset_name_prefix_hex=data.get("contract", {}).get("asset_name_prefix_hex"),
            bootstrap_generated_plutus_path=data["contract"]["bootstrap_generated_plutus_path"],
            raw=data,
        )

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "DeploymentConfig":
        path = Path(path)
        if not path.exists():
            raise CardanoNetworkClientError(f"Deployment file not found: {path}")
        return cls.from_dict(json.loads(path.read_text()))


def _normalize_deployment(deployment: Union[str, Path, DeploymentConfig]) -> DeploymentConfig:
    if isinstance(deployment, DeploymentConfig):
        return deployment
    return DeploymentConfig.from_file(deployment)


# ════════════════════════════════════════════════════════════════════════
# Funding signing key loading
# ════════════════════════════════════════════════════════════════════════

PAYMENT_DERIVATION_PATH = "m/1852'/1815'/0'/0/0"  # account 0, payment role, index 0 - matches Wallet.derive_account
STAKE_DERIVATION_PATH = "m/1852'/1815'/0'/2/0"     # account 0, stake role, index 0 - matches Wallet.derive_account


def _plutus_script_from_blueprint(blueprint: dict, compiled_code_hex: str):
    """
    Creates the correct PlutusScript type (V2 or V3) based on the
    blueprint's preamble plutusVersion field. Defaults to V2 since
    Aiken compiles to PlutusV2 by default unless 'plutus = "v3"' is
    explicitly set in aiken.toml. Getting this wrong causes silent
    ScriptFailures on real networks (Blockfrost is stricter than devnet
    about this distinction).
    """
    preamble = blueprint.get("preamble", {})
    plutus_version = preamble.get("plutusVersion", "v2").lower().strip()
    compiled_bytes = bytes.fromhex(compiled_code_hex)
    if plutus_version == "v3":
        return PlutusV3Script(compiled_bytes)
    return PlutusV2Script(compiled_bytes)



def _load_funding_signing_key(
    value: Union[str, Path], network: Network
) -> tuple[Union[PaymentSigningKey, PaymentExtendedSigningKey], Address]:
    """
    Accepts any of:
      - a path to a CLI-style skey JSON file (the standard
        {"type": "PaymentSigningKeyShelley_ed25519", "cborHex": "..."}
        envelope) - produces a non-extended PaymentSigningKey and an
        ENTERPRISE address (payment credential only, no stake part) -
        correct for standalone CLI-generated wallets that were never
        given a stake key (confirmed against this project's actual
        testnet wallet, which has no stake key file at all).
      - a raw cborHex string directly - same as above.
      - a mnemonic phrase (detected by containing whitespace / multiple
        words) - derives BOTH payment and stake EXTENDED keys via the
        same proven HD paths Wallet.derive_account already uses
        (m/1852'/1815'/0'/0/0 and .../2/0), producing a BASE address
        (payment + stake credential). This matters: an HD-derived
        wallet's real funded address always has a stake part - building
        the address from the payment credential alone produces a
        DIFFERENT, never-funded enterprise address, which is exactly the
        bug this function used to have (silently checking the wrong
        address's balance).

    Returns (signing_key, address) together rather than just the key,
    since which address shape is correct depends on which input path
    was taken - computing it separately afterward risked exactly the
    enterprise-vs-base mismatch bug above happening again.
    """
    if isinstance(value, str) and len(value.split()) > 1:
        hdwallet = HDWallet.from_mnemonic(value)
        payment_hd = hdwallet.derive_from_path(PAYMENT_DERIVATION_PATH)
        stake_hd = hdwallet.derive_from_path(STAKE_DERIVATION_PATH)
        payment_key = PaymentExtendedSigningKey.from_hdwallet(payment_hd)
        stake_key = StakeExtendedSigningKey.from_hdwallet(stake_hd)
        address = Address(
            payment_part=payment_key.to_verification_key().hash(),
            staking_part=stake_key.to_verification_key().hash(),
            network=network,
        )
        return payment_key, address

    candidate_path = Path(value) if not isinstance(value, Path) else value
    try:
        is_file = candidate_path.exists() and candidate_path.is_file()
    except OSError:
        is_file = False

    if is_file:
        data = json.loads(candidate_path.read_text())
        cbor_hex = data["cborHex"]
    else:
        cbor_hex = str(value)

    payment_key = PaymentSigningKey.from_cbor(cbor_hex)
    address = Address(payment_part=payment_key.to_verification_key().hash(), network=network)
    return payment_key, address


# ════════════════════════════════════════════════════════════════════════
# Live master state
# ════════════════════════════════════════════════════════════════════════

@dataclass
class LiveMasterState:
    utxo: UTxO
    datum: MasterDatum
    policy_id: bytes
    script_address: Address
    beacon_asset_name: bytes


@dataclass
class TxResult:
    """Returned by every write method once confirmed on-chain."""
    tx_hash: str
    confirmed: bool
    block_info: Optional[dict]
    new_master_state: Optional[LiveMasterState] = None


# ════════════════════════════════════════════════════════════════════════
# The client
# ════════════════════════════════════════════════════════════════════════

class CardanoNetworkClient:
    """
    General-purpose client for archive_registry. See module docstring for
    full design rationale.
    """

    CONFIRMATION_TIMEOUT_S = 180.0  # 60s was fine for devnet's near-instant blocks; real networks need more
    CONFIRMATION_POLL_INTERVAL_S = 2.0
    MASTER_UTXO_FLOOR_LOVELACE = 3_000_000
    TOKEN_UTXO_FLOOR_LOVELACE = 3_000_000
    TTL_BUFFER_SLOTS = 200

    def __init__(
        self,
        deployment: Union[str, Path, DeploymentConfig],
        funding_signing_key: Union[str, Path],
        operator_key: bytes,
        owner_key: Optional[bytes] = None,
        authority_key: Optional[bytes] = None,
        network_type: CardanoNet = CardanoNet.DEVNET,
    ):
        self.deployment = _normalize_deployment(deployment)
        self.network_type = network_type
        self._pycardano_network = (
            Network.MAINNET if network_type == CardanoNet.MAINNET else Network.TESTNET
        )

        if network_type == CardanoNet.DEVNET:
            self.context: ChainContext = YaciDevnetBackend(network=self._pycardano_network)
        elif network_type in (CardanoNet.TESTNET, CardanoNet.MAINNET):
            self.context = BlockFrostBackend(network=self._pycardano_network)
        else:
            raise CardanoNetworkClientError(f"Unknown network_type: {network_type}")

        self._funding_key, self._funding_address = _load_funding_signing_key(
            funding_signing_key, self._pycardano_network
        )

        self._operator_key = operator_key
        self._owner_key = owner_key
        self._authority_key = authority_key

        self._policy_id = bytes.fromhex(self.deployment.policy_id_hex)
        self._beacon_asset_name = bytes.fromhex(self.deployment.beacon_asset_name_hex)
        self._script_address = Address.from_primitive(self.deployment.script_address)

        blueprint = json.loads(Path(self.deployment.bootstrap_generated_plutus_path).read_text())
        spend_validator = next(
            (v for v in blueprint["validators"] if v["title"].endswith(".spend")), None
        )
        if spend_validator is None:
            raise CardanoNetworkClientError(
                f"No '.spend' validator found in {self.deployment.bootstrap_generated_plutus_path}"
            )
        self._script = _plutus_script_from_blueprint(blueprint, spend_validator["compiledCode"])

    # ════════════════════════════════════════════════════════════════
    # Internal: key requirement checks
    # ════════════════════════════════════════════════════════════════

    def _require_operator(self) -> bytes:
        if self._operator_key is None:
            raise MissingKeyError("operator")
        return self._operator_key

    def _require_owner(self) -> bytes:
        if self._owner_key is None:
            raise MissingKeyError("owner")
        return self._owner_key

    def _require_authority(self) -> bytes:
        if self._authority_key is None:
            raise MissingKeyError("authority")
        return self._authority_key

    @staticmethod
    def _sign_ed25519(private_key_32: bytes, message: bytes) -> bytes:
        from nacl.signing import SigningKey
        return SigningKey(private_key_32).sign(message).signature

    @staticmethod
    def _int_to_be_bytes(value: int, length: int) -> bytes:
        return value.to_bytes(length, byteorder="big", signed=False)

    # ════════════════════════════════════════════════════════════════
    # Internal: live state reading
    # ════════════════════════════════════════════════════════════════

    def _get_script_address_items(self) -> list[tuple[UTxO, Optional[bytes]]]:
        """
        Returns (UTxO, datum_cbor_bytes_or_None) pairs for every UTXO at
        the registry's script address. Backend-aware: YaciDevnetBackend's
        utxos() doesn't surface datum content at all (see its
        get_raw_utxos docstring), so that path goes through raw items
        directly; BlockFrostBackend (the official pycardano
        implementation) is trusted to populate .datum correctly on its
        own UTxO objects.
        """
        if hasattr(self.context, "get_raw_utxos"):
            raw_items = self.context.get_raw_utxos(self._script_address)
            results = []
            for item in raw_items:
                utxo = self.context.item_to_utxo(item)
                datum_hex = item.get("inline_datum")
                datum_bytes = bytes.fromhex(datum_hex) if datum_hex else None
                results.append((utxo, datum_bytes))
            return results
        else:
            results = []
            for u in self.context.utxos(self._script_address):
                datum_bytes = None
                if u.output.datum is not None:
                    try:
                        datum_bytes = u.output.datum.cbor
                    except AttributeError:
                        pass
                results.append((u, datum_bytes))
            return results

    def _find_master_utxo(self) -> UTxO:
        for utxo, _ in self._get_script_address_items():
            qty = utxo.output.amount.multi_asset.get(ScriptHash(self._policy_id), {}).get(
                AssetName(self._beacon_asset_name)
            )
            if qty == 1:
                return utxo
        raise CardanoNetworkClientError(
            f"No UTXO at {self._script_address} currently holds the beacon. "
            f"Has genesis run? Is deployment.json correct for this network?"
        )

    def get_master_state(self) -> LiveMasterState:
        target_utxo = self._find_master_utxo()
        datum_bytes = None
        for utxo, db in self._get_script_address_items():
            if utxo.input == target_utxo.input:
                datum_bytes = db
                break
        if datum_bytes is None:
            raise CardanoNetworkClientError("Master UTXO has no inline datum - contract state is invalid.")
        datum = MasterDatum.from_cbor(datum_bytes)
        return LiveMasterState(
            utxo=target_utxo,
            datum=datum,
            policy_id=self._policy_id,
            script_address=self._script_address,
            beacon_asset_name=self._beacon_asset_name,
        )

    def find_document(self, asset_name: bytes) -> Optional[TokenDatum]:
        for utxo, datum_bytes in self._get_script_address_items():
            qty = utxo.output.amount.multi_asset.get(ScriptHash(self._policy_id), {}).get(
                AssetName(asset_name)
            )
            if qty == 1 and datum_bytes is not None:
                try:
                    return TokenDatum.from_cbor(datum_bytes)
                except Exception:
                    continue
        return None

    def list_all_documents(self) -> list[TokenDatum]:
        results = []
        for utxo, datum_bytes in self._get_script_address_items():
            holds_beacon = utxo.output.amount.multi_asset.get(ScriptHash(self._policy_id), {}).get(
                AssetName(self._beacon_asset_name)
            ) == 1
            if holds_beacon or datum_bytes is None:
                continue
            try:
                results.append(TokenDatum.from_cbor(datum_bytes))
            except Exception:
                continue
        return results

    def get_stats(self) -> RegistryStats:
        return self.get_master_state().datum.stats

    # ════════════════════════════════════════════════════════════════
    # Internal: transaction building / signing / confirming
    # ════════════════════════════════════════════════════════════════

    def _build_master_spend_tx(
        self,
        master: LiveMasterState,
        redeemer_data,
        new_datum: MasterDatum,
        extra_outputs: Optional[list[TransactionOutput]] = None,
        mint_multi_asset: Optional[MultiAsset] = None,
        mint_redeemer=None,
    ) -> TransactionBuilder:
        beacon_multi_asset = MultiAsset({
            ScriptHash(self._policy_id): Asset({AssetName(self._beacon_asset_name): 1})
        })

        master_output = TransactionOutput(
            address=self._script_address,
            amount=Value(coin=self.MASTER_UTXO_FLOOR_LOVELACE, multi_asset=beacon_multi_asset),
            datum=new_datum,
        )
        # Min-UTxO-aware sizing: never under-fund as the datum grows.
        try:
            from pycardano import min_lovelace_post_alonzo as _min_lovelace
        except ImportError:
            from pycardano.utils import min_lovelace_post_alonzo as _min_lovelace
        min_required = _min_lovelace(master_output, self.context)
        master_coin = max(self.MASTER_UTXO_FLOOR_LOVELACE, min_required)
        master_output.amount = Value(coin=master_coin, multi_asset=beacon_multi_asset)

        builder = TransactionBuilder(
            self.context, ttl=self.context.last_block_slot + self.TTL_BUFFER_SLOTS
        )
        builder.add_input_address(self._funding_address)
        builder.add_script_input(
            utxo=master.utxo, script=self._script, redeemer=Redeemer(redeemer_data),
        )

        # Store script UTxOs + their datum bytes on the context so
        # BlockFrostBackend.evaluate_tx_cbor can pass them as the
        # additionalUtxoSet — required for Conway/PlutusV3 inline datum
        # resolution during Blockfrost script evaluation.
        if hasattr(self.context, '_script_utxos_for_eval'):
            items = self._get_script_address_items()
            master_items = [(u, db) for u, db in items
                           if u.input == master.utxo.input]
            self.context._script_utxos_for_eval = master_items
        builder.add_output(master_output)
        for out in (extra_outputs or []):
            builder.add_output(out)
        if mint_multi_asset is not None:
            builder.add_minting_script(self._script, Redeemer(mint_redeemer))
            builder.mint = mint_multi_asset

        return builder

    @staticmethod
    def _sign_and_submit_static(
        builder: TransactionBuilder, context: ChainContext, signing_key, change_address: Address,
    ) -> str:
        signed_tx = builder.build_and_sign(signing_keys=[signing_key], change_address=change_address)
        tx_hash = str(signed_tx.id)
        context.submit_tx(signed_tx)
        return tx_hash

    @staticmethod
    def _wait_for_confirmation_static(
        context: ChainContext, tx_hash: str,
        timeout_s: float = 60.0, poll_interval_s: float = 2.0,
    ) -> dict:
        deadline = time.monotonic() + timeout_s
        while True:
            status = context.get_tx_status(tx_hash)
            if status is not None:
                return status
            if time.monotonic() >= deadline:
                raise ConfirmationTimeoutError(tx_hash, timeout_s)
            time.sleep(poll_interval_s)

    def _sign_and_submit(self, builder: TransactionBuilder) -> str:
        return self._sign_and_submit_static(builder, self.context, self._funding_key, self._funding_address)

    def _wait_for_confirmation(
        self, tx_hash: str, timeout_s: Optional[float] = None, poll_interval_s: Optional[float] = None,
    ) -> dict:
        return self._wait_for_confirmation_static(
            self.context, tx_hash,
            timeout_s if timeout_s is not None else self.CONFIRMATION_TIMEOUT_S,
            poll_interval_s if poll_interval_s is not None else self.CONFIRMATION_POLL_INTERVAL_S,
        )

    def _execute_and_confirm(self, builder: TransactionBuilder) -> TxResult:
        tx_hash = self._sign_and_submit(builder)
        block_info = self._wait_for_confirmation(tx_hash)
        new_state = None
        try:
            new_state = self.get_master_state()
        except Exception:
            pass  # confirmation succeeded even if re-fetch fails; don't mask success
        return TxResult(tx_hash=tx_hash, confirmed=True, block_info=block_info, new_master_state=new_state)

    @staticmethod
    def _carry_forward(old: MasterDatum, **overrides) -> MasterDatum:
        fields = dict(
            authority_key=old.authority_key, operator_key=old.operator_key, owner_key=old.owner_key,
            owner_address=old.owner_address, nonce=old.nonce + 1, is_paused=old.is_paused,
            policy_id=old.policy_id, asset_name_prefix=old.asset_name_prefix,
            forward_link=old.forward_link, backward_link=old.backward_link, stats=old.stats,
        )
        fields.update(overrides)
        return MasterDatum(**fields)

    # ════════════════════════════════════════════════════════════════
    # Write: MintDocument
    # ════════════════════════════════════════════════════════════════

    def mint_document(
        self, cross_chain_global_id: bytes, sha256_hash: bytes, upload_date: bytes,
        version: int, token_data: bytes, is_unique_document: bool, valid_lower_bound: int,
    ) -> TxResult:
        operator_key = self._require_operator()
        master = self.get_master_state()
        old_datum = master.datum
        nonce = old_datum.nonce

        signed_payload = (
            self._int_to_be_bytes(nonce, 8) + cross_chain_global_id + sha256_hash
            + self._int_to_be_bytes(version, 4)
        )
        signature = self._sign_ed25519(operator_key, signed_payload)

        redeemer = MintDocument(
            nonce=nonce, cross_chain_global_id=cross_chain_global_id, sha256_hash=sha256_hash,
            upload_date=upload_date, version=version, token_data=token_data,
            is_unique_document=AikenTrue() if is_unique_document else AikenFalse(),
            valid_lower_bound=valid_lower_bound, signature=signature,
        )

        asset_name = old_datum.asset_name_prefix + self._int_to_be_bytes(nonce, 4)
        token_id = self._policy_id + asset_name
        expected_unique_inc = 1 if is_unique_document else 0

        new_datum = self._carry_forward(
            old_datum,
            stats=RegistryStats(
                total_token_count=old_datum.stats.total_token_count + 1,
                total_unique_documents=old_datum.stats.total_unique_documents + expected_unique_inc,
                last_minted_at=valid_lower_bound,
                last_cross_chain_global_id=cross_chain_global_id,
                last_cardano_asset_id=token_id,
            ),
        )

        token_datum = TokenDatum(
            cardano_asset_id=token_id, cross_chain_global_id=cross_chain_global_id,
            registry_address=b"", policy_id=self._policy_id,
            source_registry_master_utxo_reference=OutputReference(
                transaction_id=master.utxo.input.transaction_id.payload,
                output_index=master.utxo.input.index,
            ),
            sha256_hash=sha256_hash, upload_date=upload_date, version=version, token_data=token_data,
        )

        token_multi_asset = MultiAsset({ScriptHash(self._policy_id): Asset({AssetName(asset_name): 1})})
        token_output = TransactionOutput(
            address=self._script_address,  # PERMANENT lock - see registry_contract.ak header
            amount=Value(coin=self.TOKEN_UTXO_FLOOR_LOVELACE, multi_asset=token_multi_asset),
            datum=token_datum,
        )

        builder = self._build_master_spend_tx(
            master, redeemer, new_datum, extra_outputs=[token_output],
            mint_multi_asset=token_multi_asset, mint_redeemer=MintToken(),
        )
        return self._execute_and_confirm(builder)

    # ════════════════════════════════════════════════════════════════
    # Write: Pause / Resume
    # ════════════════════════════════════════════════════════════════

    def pause(self) -> TxResult:
        authority_key = self._require_authority()
        master = self.get_master_state()
        old_datum = master.datum
        nonce = old_datum.nonce
        signature = self._sign_ed25519(authority_key, self._int_to_be_bytes(nonce, 8) + b"PAUSE")
        redeemer = Pause(nonce=nonce, signature=signature)
        new_datum = self._carry_forward(old_datum, is_paused=AikenTrue())
        builder = self._build_master_spend_tx(master, redeemer, new_datum)
        return self._execute_and_confirm(builder)

    def resume(self) -> TxResult:
        authority_key = self._require_authority()
        master = self.get_master_state()
        old_datum = master.datum
        nonce = old_datum.nonce
        signature = self._sign_ed25519(authority_key, self._int_to_be_bytes(nonce, 8) + b"RESUME")
        redeemer = Resume(nonce=nonce, signature=signature)
        new_datum = self._carry_forward(old_datum, is_paused=AikenFalse())
        builder = self._build_master_spend_tx(master, redeemer, new_datum)
        return self._execute_and_confirm(builder)

    # ════════════════════════════════════════════════════════════════
    # Write: Withdraw
    # ════════════════════════════════════════════════════════════════

    def withdraw(self, amount: int, destination_address: Optional[Address] = None) -> TxResult:
        owner_key = self._require_owner()
        master = self.get_master_state()
        old_datum = master.datum
        nonce = old_datum.nonce
        signature = self._sign_ed25519(
            owner_key, self._int_to_be_bytes(nonce, 8) + b"WITHDRAW" + self._int_to_be_bytes(amount, 8)
        )
        redeemer = Withdraw(nonce=nonce, amount=amount, signature=signature)
        new_datum = self._carry_forward(old_datum)

        payout_address = destination_address or self._funding_address
        withdrawal_output = TransactionOutput(address=payout_address, amount=Value(coin=amount))

        builder = self._build_master_spend_tx(master, redeemer, new_datum, extra_outputs=[withdrawal_output])
        return self._execute_and_confirm(builder)

    # ════════════════════════════════════════════════════════════════
    # Write: RotateKey
    # ════════════════════════════════════════════════════════════════

    def rotate_key(self, key_type: str, new_key: bytes) -> TxResult:
        """key_type: 'authority' | 'operator' | 'owner'"""
        authority_key = self._require_authority()
        master = self.get_master_state()
        old_datum = master.datum
        nonce = old_datum.nonce

        tag_map = {"authority": (AuthorityKeyTag(), b"AUTHORITY"), "operator": (OperatorKeyTag(), b"OPERATOR"), "owner": (OwnerKeyTag(), b"OWNER")}
        if key_type not in tag_map:
            raise CardanoNetworkClientError(f"key_type must be one of {list(tag_map)}, got {key_type!r}")
        key_tag, key_tag_bytes = tag_map[key_type]

        signature = self._sign_ed25519(
            authority_key, self._int_to_be_bytes(nonce, 8) + b"ROTATE" + key_tag_bytes + new_key
        )
        redeemer = RotateKey(nonce=nonce, key_type=key_tag, new_key=new_key, signature=signature)

        overrides = {f"{key_type}_key": new_key}
        new_datum = self._carry_forward(old_datum, **overrides)

        builder = self._build_master_spend_tx(master, redeemer, new_datum)
        result = self._execute_and_confirm(builder)

        # Keep the client's own in-memory key in sync if it just rotated itself.
        if key_type == "authority":
            self._authority_key = new_key
        elif key_type == "operator":
            self._operator_key = new_key
        elif key_type == "owner":
            self._owner_key = new_key
        return result

    # ════════════════════════════════════════════════════════════════
    # Write: LinkForward / LinkBackward
    # ════════════════════════════════════════════════════════════════

    def link_forward(
        self, next_script_address: bytes, next_policy_id: bytes, link_reason: bytes,
        linked_at: int, instructions: bytes,
    ) -> TxResult:
        authority_key = self._require_authority()
        master = self.get_master_state()
        old_datum = master.datum
        nonce = old_datum.nonce

        signature = self._sign_ed25519(
            authority_key,
            self._int_to_be_bytes(nonce, 8) + next_policy_id + next_script_address + link_reason,
        )
        redeemer = LinkForward(
            nonce=nonce, next_script_address=next_script_address, next_policy_id=next_policy_id,
            link_reason=link_reason, linked_at=linked_at, instructions=instructions, signature=signature,
        )
        chain_link = DeploymentChainLink(
            next_script_address=next_script_address, next_policy_id=next_policy_id,
            link_reason=link_reason, linked_at=linked_at, instructions=instructions,
            current_authority_key=old_datum.authority_key, signature=signature, nonce_at_link=nonce,
        )
        new_datum = self._carry_forward(old_datum, forward_link=SomeChainLink(value=chain_link))
        builder = self._build_master_spend_tx(master, redeemer, new_datum)
        return self._execute_and_confirm(builder)

    def link_backward(
        self, prev_script_address: bytes, prev_policy_id: bytes, link_reason: bytes,
        linked_at: int, instructions: bytes,
    ) -> TxResult:
        authority_key = self._require_authority()
        master = self.get_master_state()
        old_datum = master.datum
        nonce = old_datum.nonce

        signature = self._sign_ed25519(
            authority_key,
            self._int_to_be_bytes(nonce, 8) + prev_policy_id + prev_script_address + link_reason,
        )
        redeemer = LinkBackward(
            nonce=nonce, prev_script_address=prev_script_address, prev_policy_id=prev_policy_id,
            link_reason=link_reason, linked_at=linked_at, instructions=instructions, signature=signature,
        )
        chain_link = DeploymentChainLink(
            next_script_address=prev_script_address, next_policy_id=prev_policy_id,
            link_reason=link_reason, linked_at=linked_at, instructions=instructions,
            current_authority_key=old_datum.authority_key, signature=signature, nonce_at_link=nonce,
        )
        new_datum = self._carry_forward(old_datum, backward_link=SomeChainLink(value=chain_link))
        builder = self._build_master_spend_tx(master, redeemer, new_datum)
        return self._execute_and_confirm(builder)

    # ════════════════════════════════════════════════════════════════
    # Genesis: pure class-level functionality, deliberately NOT an
    # instance method
    # ════════════════════════════════════════════════════════════════
    #
    # A CardanoNetworkClient INSTANCE represents interaction with an
    # ALREADY-DEPLOYED contract - that's the entire reason its
    # constructor requires a DeploymentConfig describing something that
    # already exists. Genesis is conceptually different: it's the act of
    # making a deployment exist in the first place. Putting it on an
    # instance (even via a classmethod that quietly constructs one
    # internally) blurs that boundary - it implies operating on a
    # deployment that isn't real yet. So genesis lives ENTIRELY at the
    # class level here: no self anywhere, no instance constructed until
    # (optionally) after genesis has genuinely succeeded.
    #
    # Two tiers:
    #   initiate_contract_genesis() - the actual genesis mechanics only.
    #       Builds and submits the genesis transaction directly. Returns
    #       a GenesisResult with everything about what was deployed -
    #       NOT a client, since handing back something that represents
    #       "ongoing interaction" isn't this function's concern.
    #   deploy_contract() - the convenience wrapper. Calls
    #       initiate_contract_genesis() first, and only once the
    #       deployment genuinely exists does it construct and return a
    #       CardanoNetworkClient instance pointed at it - consistent,
    #       since at that point the instance represents real, already-
    #       existing interaction, exactly what an instance is for.
    #
    # A client built this way is NOT special or "more authoritative"
    # than one built later via the plain constructor against the same
    # deployment.json - the client holds no meaningful state of its own
    # beyond in-memory key tracking (kept in sync by rotate_key()).
    # Discarding deploy_contract()'s returned client and constructing a
    # fresh one later, pointed at the same deployment.json, is fully
    # equivalent.

    @dataclass(frozen=True)
    class GenesisResult:
        tx_result: TxResult
        policy_id_hex: str
        script_address: str
        beacon_asset_name_hex: str
        bootstrap_generated_plutus_path: str
        deployment_json_path: Optional[str]

    @classmethod
    def initiate_contract_genesis(
        cls,
        funding_signing_key: Union[str, Path],
        operator_key: bytes,
        authority_key: bytes,
        owner_key: bytes,
        network_type: CardanoNet,
        beacon_asset_name: bytes,
        asset_name_prefix: bytes,
        source_blueprint_path: Union[str, Path],
        output_blueprint_path: Union[str, Path],
        genesis_utxo: Optional[UTxO] = None,
        owner_address: Optional[PlutusAddress] = None,
        deployment_json_output_path: Optional[Union[str, Path]] = None,
    ) -> "CardanoNetworkClient.GenesisResult":
        """
        Pure class-level genesis. No CardanoNetworkClient instance is
        constructed anywhere in this function. Compiles + parameterizes
        archive_registry against genesis_utxo (auto-selected if not
        given: largest plain-ADA UTXO over 5 ADA at the funding address),
        spends it while minting the beacon and seeding the initial
        MasterDatum in one transaction, waits for confirmation, and
        optionally writes deployment.json.
        """
        pycardano_network = Network.MAINNET if network_type == CardanoNet.MAINNET else Network.TESTNET

        if network_type == CardanoNet.DEVNET:
            context: ChainContext = YaciDevnetBackend(network=pycardano_network)
        else:
            context = BlockFrostBackend(network=pycardano_network)

        funding_key, funding_address = _load_funding_signing_key(funding_signing_key, pycardano_network)

        if genesis_utxo is None:
            candidates = [
                u for u in context.utxos(funding_address)
                if len(u.output.amount.multi_asset) == 0 and u.output.amount.coin > 5_000_000
            ]
            if not candidates:
                raise CardanoNetworkClientError(
                    f"No plain-ADA UTXO over 5 ADA found at {funding_address} to use as genesis_utxo. "
                    f"Fund this address first, or pass genesis_utxo explicitly."
                )
            genesis_utxo = max(candidates, key=lambda u: u.output.amount.coin)

        genesis_ref = OutputReference(
            transaction_id=genesis_utxo.input.transaction_id.payload,
            output_index=genesis_utxo.input.index,
        )

        applied = AikenBlueprint.apply_parameters(
            genesis_ref=genesis_ref,
            beacon_asset_name=beacon_asset_name,
            source_blueprint_path=source_blueprint_path,
            output_blueprint_path=output_blueprint_path,
        )
        policy_id = bytes.fromhex(applied.policy_id_hex)
        script_address = Address(payment_part=ScriptHash(policy_id), network=pycardano_network)
        blueprint_data = json.loads(Path(output_blueprint_path).read_text())
        script = _plutus_script_from_blueprint(blueprint_data, applied.compiled_code_hex)

        if owner_address is None:
            payment_cred = VerificationKeyCredential(bytes(funding_address.payment_part))
            if funding_address.staking_part is not None:
                stake_cred = SomeStakeCredential(
                    InlineStakeCredential(VerificationKeyCredential(bytes(funding_address.staking_part)))
                )
            else:
                from CardanoDeployer.cardano_types import NoneStakeCredential
                stake_cred = NoneStakeCredential()
            owner_address = PlutusAddress(payment_credential=payment_cred, stake_credential=stake_cred)

        for name, value in [("authority_key", authority_key), ("operator_key", operator_key), ("owner_key", owner_key)]:
            if value is None or len(value) != 32:
                raise CardanoNetworkClientError(
                    f"Genesis requires all three role keys (authority/operator/owner) "
                    f"to be set and 32 bytes each - {name} is missing or invalid."
                )

        genesis_datum = MasterDatum(
            authority_key=authority_key, operator_key=operator_key, owner_key=owner_key,
            owner_address=owner_address, nonce=0, is_paused=AikenFalse(),
            policy_id=policy_id, asset_name_prefix=asset_name_prefix,
            forward_link=NoneChainLink(), backward_link=NoneChainLink(),
            stats=RegistryStats(
                total_token_count=0, total_unique_documents=0, last_minted_at=0,
                last_cross_chain_global_id=b"", last_cardano_asset_id=b"",
            ),
        )

        beacon_multi_asset = MultiAsset({ScriptHash(policy_id): Asset({AssetName(beacon_asset_name): 1})})

        builder = TransactionBuilder(context, ttl=context.last_block_slot + cls.TTL_BUFFER_SLOTS)
        builder.add_input(genesis_utxo)
        builder.add_minting_script(script, Redeemer(MintBeacon()))
        builder.mint = beacon_multi_asset
        builder.add_output(TransactionOutput(
            address=script_address,
            amount=Value(coin=cls.MASTER_UTXO_FLOOR_LOVELACE, multi_asset=beacon_multi_asset),
            datum=genesis_datum,
        ))

        tx_hash = cls._sign_and_submit_static(builder, context, funding_key, funding_address)

        # Write the complete, fully-populated deployment.json immediately
        # after submission. tx_hash is already known at this point (it's
        # computed locally from the signed transaction before submission,
        # same as everywhere else in this client). Confirmation polling
        # happens AFTER this write, so a timeout can never lose any data.
        if deployment_json_output_path is not None:
            complete_record = {
                "network": network_type.value,
                "deployed_from_wallet_address": str(funding_address),
                "transaction_hash": tx_hash,
                "genesis_transaction_hash": genesis_utxo.input.transaction_id.payload.hex(),
                "genesis_output_index": genesis_utxo.input.index,
                "contract": {
                    "policy_id": applied.policy_id_hex,
                    "script_address": str(script_address),
                    "bootstrap_generated_plutus_path": str(output_blueprint_path),
                },
                "beacon": {
                    "asset_name_hex": beacon_asset_name.hex(),
                    "asset_name_utf8": beacon_asset_name.decode("utf-8", errors="replace"),
                },
            }
            Path(deployment_json_output_path).write_text(json.dumps(complete_record, indent=2))
            print(f"[genesis] deployment.json written: {deployment_json_output_path}")
            print(f"[genesis] policy_id:      {applied.policy_id_hex}")
            print(f"[genesis] script_address: {script_address}")
            print(f"[genesis] tx_hash:        {tx_hash}")
        print(f"[genesis] Waiting for on-chain confirmation...")
        block_info = cls._wait_for_confirmation_static(
            context, tx_hash, cls.CONFIRMATION_TIMEOUT_S, cls.CONFIRMATION_POLL_INTERVAL_S
        )
        tx_result = TxResult(tx_hash=tx_hash, confirmed=True, block_info=block_info, new_master_state=None)

        deployment_json_path_str = str(deployment_json_output_path) if deployment_json_output_path is not None else None

        return cls.GenesisResult(
            tx_result=tx_result,
            policy_id_hex=applied.policy_id_hex,
            script_address=str(script_address),
            beacon_asset_name_hex=beacon_asset_name.hex(),
            bootstrap_generated_plutus_path=str(output_blueprint_path),
            deployment_json_path=deployment_json_path_str,
        )

    @classmethod
    def deploy_contract(
        cls,
        funding_signing_key: Union[str, Path],
        operator_key: bytes,
        authority_key: bytes,
        owner_key: bytes,
        network_type: CardanoNet,
        beacon_asset_name: bytes,
        asset_name_prefix: bytes,
        source_blueprint_path: Union[str, Path],
        output_blueprint_path: Union[str, Path],
        genesis_utxo: Optional[UTxO] = None,
        owner_address: Optional[PlutusAddress] = None,
        deployment_json_output_path: Optional[Union[str, Path]] = None,
    ) -> tuple["CardanoNetworkClient", "CardanoNetworkClient.GenesisResult"]:
        """
        Convenience wrapper: runs initiate_contract_genesis(), then -
        only once the deployment genuinely exists on-chain - constructs
        and returns a ready-to-use CardanoNetworkClient instance pointed
        at it, alongside the GenesisResult. The returned client is not
        special; discarding it and constructing a fresh one later via
        the plain constructor + the same deployment.json is equivalent.

        deployment_json_output_path should be given here (vs. left None)
        in essentially all real uses, since otherwise there's no
        deployment.json for any later client construction to point at.
        """
        genesis = cls.initiate_contract_genesis(
            funding_signing_key=funding_signing_key, operator_key=operator_key,
            authority_key=authority_key, owner_key=owner_key, network_type=network_type,
            beacon_asset_name=beacon_asset_name, asset_name_prefix=asset_name_prefix,
            source_blueprint_path=source_blueprint_path, output_blueprint_path=output_blueprint_path,
            genesis_utxo=genesis_utxo, owner_address=owner_address,
            deployment_json_output_path=deployment_json_output_path,
        )

        deployment_config = DeploymentConfig(
            policy_id_hex=genesis.policy_id_hex,
            script_address=genesis.script_address,
            beacon_asset_name_hex=genesis.beacon_asset_name_hex,
            asset_name_prefix_hex=asset_name_prefix.hex(),
            bootstrap_generated_plutus_path=genesis.bootstrap_generated_plutus_path,
            raw={},
        )
        client = cls(
            deployment=deployment_config,
            funding_signing_key=funding_signing_key,
            operator_key=operator_key,
            authority_key=authority_key,
            owner_key=owner_key,
            network_type=network_type,
        )
        return client, genesis

