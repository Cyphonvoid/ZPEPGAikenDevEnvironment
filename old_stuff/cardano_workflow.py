"""
cardano_workflow.py - ZPEPG deployment workflow components.

All classes here are namespace classes (no instantiation needed) except
where a real instance is necessary. Each class owns its own constants,
error types, and logic. Nothing in this file does input-gathering,
prompting, or CLI argument parsing - that lives in cardano_deploy.py.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from fractions import Fraction
from pathlib import Path
from typing import Union

from pycardano import (
    Address, Asset, AssetName, MultiAsset, Network,
    PaymentExtendedSigningKey, PaymentVerificationKey,
    PlutusV3Script, ProtocolParameters,
    Redeemer, ScriptHash, StakeExtendedSigningKey, StakeVerificationKey,
    TransactionBuilder, TransactionId, TransactionInput,
    TransactionOutput, UTxO, Value, HDWallet,
)
from pycardano.backend.base import ChainContext
from pycardano.plutus import ExecutionUnits

from cardano_types import (
    AikenFalse, InlineStakeCredential, MasterDatum, MintBeacon,
    NoneChainLink, OutputReference, PlutusAddress, RegistryStats,
    SomeStakeCredential, VerificationKeyCredential,
)
from cardano_network import NetworkBackend, NetworkError, UtxoInfo


# ═══════════════════════════════════════════════════════════════════════════
# Wallet - mnemonic derivation, address scanning and verification
# ═══════════════════════════════════════════════════════════════════════════

class Wallet:
    """
    Namespace for mnemonic-based wallet derivation and address verification.

    Users know their address, not their derivation account index. resolve()
    scans a range of indices, derives the address at each, and finds which
    one matches the supplied address - so the index never needs to be
    known or supplied externally.
    """

    PURPOSE = 1852
    COIN_TYPE = 1815
    PAYMENT_ROLE = 0
    STAKE_ROLE = 2
    ADDRESS_INDEX = 0
    DEFAULT_SCAN_RANGE = range(0, 20)

    class NotFoundError(Exception):
        def __init__(self, address: str, scan_range: range):
            self.address = address
            self.scan_range = scan_range
            super().__init__(
                f"Address {address!r} not found in derivation range "
                f"{scan_range.start}-{scan_range.stop - 1} for the given mnemonic. "
                f"Check the address/mnemonic, or pass a wider scan_range."
            )

    @dataclass(frozen=True)
    class DerivedAccount:
        account_index: int
        payment_signing_key: PaymentExtendedSigningKey
        payment_verification_key: PaymentVerificationKey
        stake_signing_key: StakeExtendedSigningKey
        stake_verification_key: StakeVerificationKey
        address: Address

        def __repr__(self) -> str:
            # Deliberately omit signing keys from repr
            return f"DerivedAccount(index={self.account_index}, address={self.address})"

    @classmethod
    def derive_account(cls, hdwallet: HDWallet, account_index: int, network: Network) -> "Wallet.DerivedAccount":
        payment_path = f"m/{cls.PURPOSE}'/{cls.COIN_TYPE}'/{account_index}'/{cls.PAYMENT_ROLE}/{cls.ADDRESS_INDEX}"
        stake_path   = f"m/{cls.PURPOSE}'/{cls.COIN_TYPE}'/{account_index}'/{cls.STAKE_ROLE}/{cls.ADDRESS_INDEX}"

        p_hd  = hdwallet.derive_from_path(payment_path)
        p_esk = PaymentExtendedSigningKey.from_hdwallet(p_hd)
        p_evk = p_esk.to_verification_key()

        s_hd  = hdwallet.derive_from_path(stake_path)
        s_esk = StakeExtendedSigningKey.from_hdwallet(s_hd)
        s_evk = s_esk.to_verification_key()

        address = Address(
            payment_part=p_evk.hash(),
            staking_part=s_evk.hash(),
            network=network,
        )
        return Wallet.DerivedAccount(
            account_index=account_index,
            payment_signing_key=p_esk,
            payment_verification_key=p_evk,
            stake_signing_key=s_esk,
            stake_verification_key=s_evk,
            address=address,
        )

    @classmethod
    def resolve(
        cls,
        mnemonic: str,
        expected_address: str,
        network: Network,
        scan_range: range = None,
    ) -> "Wallet.DerivedAccount":
        if scan_range is None:
            scan_range = cls.DEFAULT_SCAN_RANGE

        hdwallet = HDWallet.from_mnemonic(mnemonic)
        target = Address.from_primitive(expected_address)

        if target.network != network:
            raise ValueError(
                f"Address is on network {target.network}, bootstrap is targeting {network}."
            )

        for idx in scan_range:
            candidate = cls.derive_account(hdwallet, idx, network)
            if candidate.address == target:
                return candidate

        raise Wallet.NotFoundError(expected_address, scan_range)


# ═══════════════════════════════════════════════════════════════════════════
# PermKeys - permission key set loading from perm_keys.json
# ═══════════════════════════════════════════════════════════════════════════

class PermKeys:
    """
    Namespace for loading and validating perm_keys.json.

    The permission key set (authority/operator/owner) is separate from the
    funding wallet. These are bare Ed25519 keypairs baked into MasterDatum
    as VerificationKeys, checked on-chain via verify_ed25519_signature for
    future redeemer actions (RotateKey, Pause, MintDocument, etc.).

    Bootstrap only needs the PUBLIC halves. Private keys are validated for
    structural correctness then immediately discarded - never logged, never
    persisted, never passed downstream.
    """

    REQUIRED_ROLES = ("authority", "operator", "owner")
    REQUIRED_FIELDS = ("private_key_hex", "public_key_hex")
    KEY_LENGTH_BYTES = 32

    EXAMPLE_STRUCTURE = """{
        "authority": {
            "private_key_hex": "<64 hex chars>",
            "public_key_hex":  "<64 hex chars>"
        },
        "operator": {
            "private_key_hex": "<64 hex chars>",
            "public_key_hex":  "<64 hex chars>"
        },
        "owner": {
            "private_key_hex": "<64 hex chars>",
            "public_key_hex":  "<64 hex chars>"
        }
    }"""

    class Error(Exception):
        def __init__(self, reason: str):
            super().__init__(
                f"{reason}\n\n"
                f"perm_keys.json must have this structure:\n\n"
                f"{PermKeys.EXAMPLE_STRUCTURE}"
            )

    @dataclass(frozen=True)
    class KeySet:
        """Public-only view. Safe to log, embed in deployment.json, pass anywhere."""
        authority_key: bytes
        operator_key: bytes
        owner_key: bytes

        def as_dict(self) -> dict[str, str]:
            return {
                "authority_key": self.authority_key.hex(),
                "operator_key":  self.operator_key.hex(),
                "owner_key":     self.owner_key.hex(),
            }

    @classmethod
    def _validate_hex(cls, role: str, field: str, value) -> bytes:
        if not isinstance(value, str):
            raise PermKeys.Error(f"'{role}.{field}' must be a hex string, got {type(value).__name__}.")
        try:
            raw = bytes.fromhex(value)
        except ValueError as e:
            raise PermKeys.Error(f"'{role}.{field}' is not valid hex: {e}") from e
        if len(raw) != cls.KEY_LENGTH_BYTES:
            raise PermKeys.Error(
                f"'{role}.{field}' must be {cls.KEY_LENGTH_BYTES} bytes "
                f"({cls.KEY_LENGTH_BYTES * 2} hex chars), got {len(raw)}."
            )
        return raw

    @classmethod
    def load(cls, path: str | Path) -> "PermKeys.KeySet":
        path = Path(path)
        if not path.exists():
            raise PermKeys.Error(f"perm_keys.json not found at: {path}")
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            raise PermKeys.Error(f"perm_keys.json is not valid JSON: {e}") from e
        if not isinstance(data, dict):
            raise PermKeys.Error(f"perm_keys.json must be a JSON object, got {type(data).__name__}.")

        missing = [r for r in cls.REQUIRED_ROLES if r not in data]
        if missing:
            raise PermKeys.Error(f"perm_keys.json missing role(s): {', '.join(missing)}")

        public_keys = {}
        for role in cls.REQUIRED_ROLES:
            role_data = data[role]
            if not isinstance(role_data, dict):
                raise PermKeys.Error(f"'{role}' must be an object, got {type(role_data).__name__}.")
            missing_fields = [f for f in cls.REQUIRED_FIELDS if f not in role_data]
            if missing_fields:
                raise PermKeys.Error(f"'{role}' missing field(s): {', '.join(missing_fields)}")
            # Validate private key structure then discard immediately
            cls._validate_hex(role, "private_key_hex", role_data["private_key_hex"])
            del role_data
            # Only retain the public key
            public_keys[role] = cls._validate_hex(role, "public_key_hex", data[role]["public_key_hex"])

        return PermKeys.KeySet(
            authority_key=public_keys["authority"],
            operator_key=public_keys["operator"],
            owner_key=public_keys["owner"],
        )


# ═══════════════════════════════════════════════════════════════════════════
# AikenBlueprint - beacon_policy parameterization via aiken CLI
# ═══════════════════════════════════════════════════════════════════════════

class AikenBlueprint:
    """
    Namespace for aiken blueprint apply subprocess calls.

    Shells out to the aiken CLI rather than reimplementing UPLC term
    application in Python - the CLI is the reference implementation and
    is already confirmed working manually. Any reimplementation risks
    subtly wrong UPLC application that silently binds to the wrong UTXO.
    """

    BEACON_MODULE    = "beacon_contract"
    BEACON_VALIDATOR = "beacon_policy"
    BEACON_TITLE     = "beacon_contract.beacon_policy.mint"
    REGISTRY_TITLE   = "registry_contract.archive_registry.spend"

    class Error(Exception):
        pass

    @dataclass(frozen=True)
    class AppliedBeacon:
        beacon_policy_id_hex: str
        compiled_code_hex: str
        blueprint_path: Path

    @classmethod
    def _require_aiken(cls) -> str:
        binary = shutil.which("aiken")
        if binary is None:
            raise AikenBlueprint.Error(
                "`aiken` CLI not found on PATH. Install Aiken and confirm "
                "`aiken --version` works before retrying."
            )
        return binary

    @classmethod
    def _find_validator(cls, blueprint: dict, title: str) -> dict | None:
        return next((v for v in blueprint.get("validators", []) if v.get("title") == title), None)

    @classmethod
    def apply_beacon_parameter(
        cls,
        genesis_ref: OutputReference,
        source_blueprint_path: str | Path,
        output_blueprint_path: str | Path,
    ) -> "AikenBlueprint.AppliedBeacon":
        aiken = cls._require_aiken()
        source = Path(source_blueprint_path)
        output = Path(output_blueprint_path)

        if not source.exists():
            raise AikenBlueprint.Error(f"Source blueprint not found: {source}")

        cmd = [
            aiken, "blueprint", "apply",
            "-m", cls.BEACON_MODULE,
            "-v", cls.BEACON_VALIDATOR,
            "-i", str(source),
            "-o", str(output),
            genesis_ref.to_cbor_hex(),
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired as e:
            raise AikenBlueprint.Error(f"`aiken blueprint apply` timed out.") from e
        except OSError as e:
            raise AikenBlueprint.Error(f"Failed to invoke aiken: {e}") from e

        if result.returncode != 0:
            raise AikenBlueprint.Error(
                f"`aiken blueprint apply` failed (exit {result.returncode}).\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )

        if not output.exists():
            raise AikenBlueprint.Error(
                f"`aiken blueprint apply` succeeded but output file not found: {output}"
            )

        try:
            blueprint = json.loads(output.read_text())
        except json.JSONDecodeError as e:
            raise AikenBlueprint.Error(f"Output blueprint is not valid JSON: {e}") from e

        validator = cls._find_validator(blueprint, cls.BEACON_TITLE)
        if validator is None:
            available = [v.get("title") for v in blueprint.get("validators", [])]
            raise AikenBlueprint.Error(
                f"'{cls.BEACON_TITLE}' not found in output blueprint. "
                f"Available: {available}"
            )

        return AikenBlueprint.AppliedBeacon(
            beacon_policy_id_hex=validator["hash"],
            compiled_code_hex=validator["compiledCode"],
            blueprint_path=output,
        )

    @classmethod
    def load_registry_validator(cls, blueprint_path: str | Path) -> dict:
        path = Path(blueprint_path)
        if not path.exists():
            raise AikenBlueprint.Error(f"Blueprint not found: {path}")
        try:
            blueprint = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            raise AikenBlueprint.Error(f"Blueprint is not valid JSON: {e}") from e

        validator = cls._find_validator(blueprint, cls.REGISTRY_TITLE)
        if validator is None:
            available = [v.get("title") for v in blueprint.get("validators", [])]
            raise AikenBlueprint.Error(
                f"'{cls.REGISTRY_TITLE}' not found in blueprint. Available: {available}"
            )
        return validator


# ═══════════════════════════════════════════════════════════════════════════
# GenesisTransaction - builds, signs, and submits the genesis tx
# ═══════════════════════════════════════════════════════════════════════════

class GenesisTransaction:
    """
    Namespace for building and submitting the one-time genesis bootstrap
    transaction. Owns a minimal ChainContext subclass backed by NetworkBackend
    rather than using pccontext (which has confirmed bugs in this project).
    """

    MASTER_UTXO_LOVELACE = 3_000_000  # confirmed sufficient on-chain
    TTL_BUFFER_SLOTS     = 200        # generous buffer; adjust for mainnet

    class Error(Exception):
        pass

    @dataclass(frozen=True)
    class Result:
        tx_id: str
        master_utxo_ref: str
        registry_script_address: str
        registry_policy_id_hex: str
        beacon_policy_id_hex: str
        beacon_asset_name_hex: str

    # ── Minimal ChainContext backed by NetworkBackend ──────────────────────

    class _ProviderContext(ChainContext):
        """
        Implements only what TransactionBuilder actually calls
        (confirmed by source inspection of pycardano 0.19.2):
        evaluate_tx, last_block_slot, network, protocol_param, utxos.
        """

        def __init__(self, backend: NetworkBackend, network: Network):
            self._backend = backend
            self._network = network
            self._cached_params: ProtocolParameters | None = None

        @property
        def network(self) -> Network:
            return self._network

        @property
        def protocol_param(self) -> ProtocolParameters:
            if self._cached_params is None:
                try:
                    self._cached_params = self._backend.protocol_parameters()
                except NetworkError as e:
                    raise GenesisTransaction.Error(f"Could not fetch protocol parameters: {e}") from e
            return self._cached_params

        @property
        def last_block_slot(self) -> int:
            try:
                return self._backend.current_slot()
            except NetworkError as e:
                raise GenesisTransaction.Error(f"Could not fetch current slot: {e}") from e

        def utxos(self, address) -> list[UTxO]:
            addr_str = str(address)
            try:
                provider_utxos = self._backend.get_utxos(addr_str)
            except NetworkError as e:
                raise GenesisTransaction.Error(f"Could not fetch UTXOs for {addr_str}: {e}") from e

            results = []
            for u in provider_utxos:
                tx_input = TransactionInput(
                    transaction_id=TransactionId(bytes.fromhex(u.tx_hash)),
                    index=u.output_index,
                )
                multi_asset = MultiAsset({})
                if u.assets:
                    grouped: dict[bytes, dict[bytes, int]] = {}
                    for asset in u.assets:
                        policy_hex, _, name_hex = asset.unit.partition(".")
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
            try:
                return self._backend.evaluate_tx(cbor_bytes)
            except NetworkError as e:
                raise GenesisTransaction.Error(f"Transaction evaluation failed: {e}") from e

        def submit_tx_cbor(self, cbor) -> None:
            cbor_bytes = bytes.fromhex(cbor) if isinstance(cbor, str) else cbor
            try:
                self._backend.submit_tx(cbor_bytes)
            except NetworkError as e:
                raise GenesisTransaction.Error(f"Transaction submission failed: {e}") from e

    # ── Genesis datum / address helpers ───────────────────────────────────

    @classmethod
    def _build_owner_plutus_address(cls, account: "Wallet.DerivedAccount") -> PlutusAddress:
        return PlutusAddress(
            payment_credential=VerificationKeyCredential(
                bytes(account.payment_verification_key.hash())
            ),
            stake_credential=SomeStakeCredential(
                InlineStakeCredential(
                    VerificationKeyCredential(bytes(account.stake_verification_key.hash()))
                )
            ),
        )

    @classmethod
    def _build_master_datum(
        cls,
        perm_keys: "PermKeys.KeySet",
        owner_address: PlutusAddress,
        registry_policy_id: bytes,
        asset_name_prefix: bytes,
        beacon_policy_id: bytes,
        beacon_asset_name: bytes,
    ) -> MasterDatum:
        for name, value in [
            ("authority_key", perm_keys.authority_key),
            ("operator_key",  perm_keys.operator_key),
            ("owner_key",     perm_keys.owner_key),
        ]:
            if len(value) != 32:
                raise GenesisTransaction.Error(
                    f"{name} must be 32 bytes, got {len(value)}. "
                    f"Check perm_keys.json."
                )
        return MasterDatum(
            authority_key=perm_keys.authority_key,
            operator_key=perm_keys.operator_key,
            owner_key=perm_keys.owner_key,
            owner_address=owner_address,
            nonce=0,
            is_paused=AikenFalse(),
            policy_id=registry_policy_id,
            asset_name_prefix=asset_name_prefix,
            beacon_policy_id=beacon_policy_id,
            beacon_asset_name=beacon_asset_name,
            forward_link=NoneChainLink(),
            backward_link=NoneChainLink(),
            stats=RegistryStats(
                total_token_count=0,
                total_unique_documents=0,
                last_minted_at=0,
                last_cross_chain_global_id=b"",
                last_cardano_asset_id=b"",
            ),
        )

    # ── Main entry point ──────────────────────────────────────────────────

    @classmethod
    def run(
        cls,
        backend: NetworkBackend,
        network: Network,
        funding_account: "Wallet.DerivedAccount",
        genesis_utxo: UtxoInfo,
        beacon_compiled_code_hex: str,
        beacon_policy_id_hex: str,
        beacon_asset_name: bytes,
        registry_compiled_code_hex: str,
        registry_policy_id_hex: str,
        asset_name_prefix: bytes,
        perm_keys: "PermKeys.KeySet",
    ) -> "GenesisTransaction.Result":

        context = cls._ProviderContext(backend, network)

        registry_policy_id_bytes = bytes.fromhex(registry_policy_id_hex)
        beacon_policy_id_bytes   = bytes.fromhex(beacon_policy_id_hex)

        registry_script_address = Address(
            payment_part=ScriptHash(registry_policy_id_bytes),
            network=network,
        )
        beacon_script = PlutusV3Script(bytes.fromhex(beacon_compiled_code_hex))

        genesis_utxo_obj = UTxO(
            input=TransactionInput(
                transaction_id=TransactionId(bytes.fromhex(genesis_utxo.tx_hash)),
                index=genesis_utxo.output_index,
            ),
            output=TransactionOutput(
                address=Address.from_primitive(genesis_utxo.address),
                amount=Value(coin=genesis_utxo.lovelace),
            ),
        )

        owner_plutus_address = cls._build_owner_plutus_address(funding_account)
        genesis_master_datum = cls._build_master_datum(
            perm_keys=perm_keys,
            owner_address=owner_plutus_address,
            registry_policy_id=registry_policy_id_bytes,
            asset_name_prefix=asset_name_prefix,
            beacon_policy_id=beacon_policy_id_bytes,
            beacon_asset_name=beacon_asset_name,
        )

        beacon_multi_asset = MultiAsset({
            ScriptHash(beacon_policy_id_bytes): Asset({AssetName(beacon_asset_name): 1})
        })

        builder = TransactionBuilder(context, ttl=context.last_block_slot + cls.TTL_BUFFER_SLOTS)
        builder.add_input(genesis_utxo_obj)
        builder.add_minting_script(beacon_script, Redeemer(MintBeacon()))
        builder.mint = beacon_multi_asset
        builder.add_output(TransactionOutput(
            address=registry_script_address,
            amount=Value(coin=cls.MASTER_UTXO_LOVELACE, multi_asset=beacon_multi_asset),
            datum=genesis_master_datum,
        ))

        try:
            signed_tx = builder.build_and_sign(
                signing_keys=[funding_account.payment_signing_key],
                change_address=funding_account.address,
            )
        except Exception as e:
            raise GenesisTransaction.Error(f"Failed to build/sign genesis transaction: {e}") from e

        try:
            context.submit_tx(signed_tx)
        except Exception as e:
            raise GenesisTransaction.Error(f"Failed to submit genesis transaction: {e}") from e

        tx_id = str(signed_tx.id)
        return GenesisTransaction.Result(
            tx_id=tx_id,
            master_utxo_ref=f"{tx_id}#0",
            registry_script_address=str(registry_script_address),
            registry_policy_id_hex=registry_policy_id_hex,
            beacon_policy_id_hex=beacon_policy_id_hex,
            beacon_asset_name_hex=beacon_asset_name.hex(),
        )


# ═══════════════════════════════════════════════════════════════════════════
# DeploymentRecord - writes deployment.json
# ═══════════════════════════════════════════════════════════════════════════

class DeploymentRecord:
    """
    Namespace for building and persisting the deployment record.
    Never accepts or persists private key material.
    """

    class Error(Exception):
        pass

    @dataclass(frozen=True)
    class Record:
        network: str
        timestamp_utc: str
        deployer_address: str
        genesis_tx_hash: str
        genesis_output_index: int
        beacon_policy_id: str
        beacon_asset_name_hex: str
        beacon_asset_name_utf8: str | None
        registry_policy_id: str
        registry_script_address: str
        master_utxo_ref: str
        permission_keys: dict
        bootstrap_generated_plutus_path: str

        def to_dict(self) -> dict:
            return asdict(self)

    @classmethod
    def build(
        cls,
        network: Network,
        funding_account: "Wallet.DerivedAccount",
        genesis_utxo: UtxoInfo,
        tx_result: "GenesisTransaction.Result",
        beacon_asset_name: bytes,
        perm_keys: "PermKeys.KeySet",
        blueprint_output_path: str | Path,
    ) -> "DeploymentRecord.Record":
        try:
            asset_name_utf8 = beacon_asset_name.decode("utf-8")
        except UnicodeDecodeError:
            asset_name_utf8 = None

        return DeploymentRecord.Record(
            network=network.name,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            deployer_address=str(funding_account.address),
            genesis_tx_hash=genesis_utxo.tx_hash,
            genesis_output_index=genesis_utxo.output_index,
            beacon_policy_id=tx_result.beacon_policy_id_hex,
            beacon_asset_name_hex=tx_result.beacon_asset_name_hex,
            beacon_asset_name_utf8=asset_name_utf8,
            registry_policy_id=tx_result.registry_policy_id_hex,
            registry_script_address=tx_result.registry_script_address,
            master_utxo_ref=tx_result.master_utxo_ref,
            permission_keys=perm_keys.as_dict(),
            bootstrap_generated_plutus_path=str(blueprint_output_path),
        )

    @classmethod
    def write(
        cls,
        record: "DeploymentRecord.Record",
        output_path: str | Path,
        allow_overwrite: bool = True,
    ) -> Path:
        output_path = Path(output_path)
        if output_path.exists() and not allow_overwrite:
            raise DeploymentRecord.Error(
                f"{output_path} already exists. Refusing to overwrite an existing "
                f"deployment record. Pass allow_overwrite=True or delete the file first."
            )
        try:
            output_path.write_text(json.dumps(record.to_dict(), indent=2))
        except OSError as e:
            raise DeploymentRecord.Error(f"Could not write {output_path}: {e}") from e
        return output_path
