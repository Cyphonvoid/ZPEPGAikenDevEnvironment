"""
CardanoUtils.py - Shared Plutus type definitions and blueprint utilities
for ZPEPG Cardano smart contract interactions.

This file is the single shared dependency for CardanoClient.py and
CardanoDeployer.py. It contains:

  1. PlutusData type mirrors — on-chain type definitions matching the
     registry_contract.ak validator exactly. CONSTR_ID values and field
     ordering are verified against the compiled plutus.json.

  2. Redeemer types — all RegistryAction variants and CreateTokenAction
     variants used by the spend and mint validators.

  3. AikenBlueprint — blueprint parameterization via the aiken CLI.
     Shells out to `aiken blueprint apply` rather than reimplementing
     UPLC term application in Python.

CONSTR_ID assignment follows declaration order within each Aiken type:
  pub type X { A B C }  →  A=0, B=1, C=2

All types here are verified against registry_contract.ak source and/or
the compiled plutus.json definitions.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Union

import cbor2
from pycardano import PlutusData


# ══════════════════════════════════════════════════════════════════════════════
# cardano/transaction.OutputReference
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class OutputReference(PlutusData):
    CONSTR_ID = 0
    transaction_id: bytes
    output_index: int


# ══════════════════════════════════════════════════════════════════════════════
# Aiken Bool
# VERIFIED: False = Constr 0 [], True = Constr 1 []
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AikenFalse(PlutusData):
    CONSTR_ID = 0


@dataclass
class AikenTrue(PlutusData):
    CONSTR_ID = 1


AikenBool = Union[AikenFalse, AikenTrue]


def aiken_bool(value: bool) -> AikenBool:
    return AikenTrue() if value else AikenFalse()


# ══════════════════════════════════════════════════════════════════════════════
# cardano/address.Credential
# VERIFIED against compiled plutus.json definitions
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class VerificationKeyCredential(PlutusData):
    CONSTR_ID = 0
    credential_hash: bytes


@dataclass
class ScriptCredential(PlutusData):
    CONSTR_ID = 1
    credential_hash: bytes


Credential = Union[VerificationKeyCredential, ScriptCredential]


# ══════════════════════════════════════════════════════════════════════════════
# cardano/address.StakeCredential
# VERIFIED against compiled plutus.json definitions
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class InlineStakeCredential(PlutusData):
    CONSTR_ID = 0
    credential: Credential


@dataclass
class SomeStakeCredential(PlutusData):
    CONSTR_ID = 0
    value: InlineStakeCredential


@dataclass
class NoneStakeCredential(PlutusData):
    CONSTR_ID = 1


OptionStakeCredential = Union[SomeStakeCredential, NoneStakeCredential]


# ══════════════════════════════════════════════════════════════════════════════
# cardano/address.Address
# VERIFIED against compiled plutus.json definitions
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PlutusAddress(PlutusData):
    CONSTR_ID = 0
    payment_credential: Credential
    stake_credential: OptionStakeCredential


# ══════════════════════════════════════════════════════════════════════════════
# registry_contract.RegistryStats
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class RegistryStats(PlutusData):
    CONSTR_ID = 0
    total_token_count: int
    total_unique_documents: int
    last_minted_at: int
    last_cross_chain_global_id: bytes
    last_cardano_asset_id: bytes


# ══════════════════════════════════════════════════════════════════════════════
# registry_contract.DeploymentChainLink
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class DeploymentChainLink(PlutusData):
    CONSTR_ID = 0
    next_script_address: bytes
    next_policy_id: bytes
    link_reason: bytes
    linked_at: int
    instructions: bytes
    current_authority_key: bytes
    signature: bytes
    nonce_at_link: int


# ══════════════════════════════════════════════════════════════════════════════
# Option<DeploymentChainLink>
# VERIFIED: Some(x) = Constr 0 [x], None = Constr 1 []
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SomeChainLink(PlutusData):
    CONSTR_ID = 0
    value: DeploymentChainLink


@dataclass
class NoneChainLink(PlutusData):
    CONSTR_ID = 1


OptionChainLink = Union[SomeChainLink, NoneChainLink]


# ══════════════════════════════════════════════════════════════════════════════
# registry_contract.MasterDatum
# Field count: 11 (beacon_policy_id / beacon_asset_name removed in
# single-script architecture — canonical identity is now a compile-time
# fact, not a datum field).
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MasterDatum(PlutusData):
    CONSTR_ID = 0
    authority_key: bytes
    operator_key: bytes
    owner_key: bytes
    owner_address: PlutusAddress
    nonce: int
    is_paused: AikenBool
    policy_id: bytes
    asset_name_prefix: bytes
    forward_link: OptionChainLink
    backward_link: OptionChainLink
    stats: RegistryStats


# ══════════════════════════════════════════════════════════════════════════════
# registry_contract.TokenDatum
# Field order matches the .ak declaration exactly.
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class TokenDatum(PlutusData):
    CONSTR_ID = 0
    cardano_asset_id: bytes
    cross_chain_global_id: bytes
    registry_address: bytes
    policy_id: bytes
    source_registry_master_utxo_reference: OutputReference
    sha256_hash: bytes
    upload_date: bytes
    version: int
    token_data: bytes


# ══════════════════════════════════════════════════════════════════════════════
# registry_contract.KeyType
# pub type KeyType { AuthorityKey OperatorKey OwnerKey }
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AuthorityKeyTag(PlutusData):
    CONSTR_ID = 0


@dataclass
class OperatorKeyTag(PlutusData):
    CONSTR_ID = 1


@dataclass
class OwnerKeyTag(PlutusData):
    CONSTR_ID = 2


KeyType = Union[AuthorityKeyTag, OperatorKeyTag, OwnerKeyTag]


# ══════════════════════════════════════════════════════════════════════════════
# registry_contract.RegistryAction (spend redeemer)
# Declaration order in registry_contract.ak:
#   MintDocument=0, Pause=1, Resume=2, Withdraw=3, RotateKey=4,
#   LinkForward=5, LinkBackward=6
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MintDocument(PlutusData):
    CONSTR_ID = 0
    nonce: int
    cross_chain_global_id: bytes
    sha256_hash: bytes
    upload_date: bytes
    version: int
    token_data: bytes
    is_unique_document: AikenBool
    valid_lower_bound: int
    signature: bytes


@dataclass
class Pause(PlutusData):
    CONSTR_ID = 1
    nonce: int
    signature: bytes


@dataclass
class Resume(PlutusData):
    CONSTR_ID = 2
    nonce: int
    signature: bytes


@dataclass
class Withdraw(PlutusData):
    CONSTR_ID = 3
    nonce: int
    amount: int
    signature: bytes


@dataclass
class RotateKey(PlutusData):
    CONSTR_ID = 4
    nonce: int
    key_type: KeyType
    new_key: bytes
    signature: bytes


@dataclass
class LinkForward(PlutusData):
    CONSTR_ID = 5
    nonce: int
    next_script_address: bytes
    next_policy_id: bytes
    link_reason: bytes
    linked_at: int
    instructions: bytes
    signature: bytes


@dataclass
class LinkBackward(PlutusData):
    CONSTR_ID = 6
    nonce: int
    prev_script_address: bytes
    prev_policy_id: bytes
    link_reason: bytes
    linked_at: int
    instructions: bytes
    signature: bytes


RegistryAction = Union[
    MintDocument, Pause, Resume, Withdraw, RotateKey, LinkForward, LinkBackward
]


# ══════════════════════════════════════════════════════════════════════════════
# registry_contract.CreateTokenAction (mint redeemer)
# pub type CreateTokenAction { MintToken BurnToken MintBeacon }
# Declaration order: MintToken=0, BurnToken=1, MintBeacon=2
#
# NOTE: MintBeacon CONSTR_ID=2 (not 0) because declaration order is
# MintToken, BurnToken, MintBeacon. Getting this wrong produces silent
# on-chain rejection with wrong constructor index.
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MintToken(PlutusData):
    CONSTR_ID = 0


@dataclass
class BurnToken(PlutusData):
    CONSTR_ID = 1


@dataclass
class MintBeacon(PlutusData):
    CONSTR_ID = 2


CreateTokenAction = Union[MintToken, BurnToken, MintBeacon]


# ══════════════════════════════════════════════════════════════════════════════
# AikenBlueprint — blueprint parameterization via aiken CLI
#
# Shells out to `aiken blueprint apply` rather than reimplementing UPLC
# term application in Python. archive_registry declares TWO parameters:
#   validator archive_registry(genesis_ref: OutputReference, beacon_asset_name: ByteArray)
# So two sequential apply calls are needed:
#   1. apply genesis_ref  → intermediate blueprint
#   2. apply beacon_asset_name → final blueprint
# ══════════════════════════════════════════════════════════════════════════════

class AikenBlueprint:

    MODULE      = "registry_contract"
    VALIDATOR   = "archive_registry"
    SPEND_TITLE = "registry_contract.archive_registry.spend"
    MINT_TITLE  = "registry_contract.archive_registry.mint"

    class Error(Exception):
        pass

    @dataclass(frozen=True)
    class AppliedScript:
        policy_id_hex: str
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
        return next(
            (v for v in blueprint.get("validators", []) if v.get("title") == title),
            None,
        )

    @classmethod
    def _run_apply(cls, aiken: str, source: Path, output: Path, param_cbor_hex: str) -> None:
        cmd = [
            aiken, "blueprint", "apply",
            "-m", cls.MODULE,
            "-v", cls.VALIDATOR,
            "-i", str(source),
            "-o", str(output),
            param_cbor_hex,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired as e:
            raise AikenBlueprint.Error("`aiken blueprint apply` timed out.") from e
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

    @classmethod
    def apply_parameters(
        cls,
        genesis_ref: OutputReference,
        beacon_asset_name: bytes,
        source_blueprint_path: str | Path,
        output_blueprint_path: str | Path,
    ) -> "AikenBlueprint.AppliedScript":
        """
        Apply genesis_ref and beacon_asset_name to the source blueprint,
        producing a fully-parameterized blueprint at output_blueprint_path.

        Returns AppliedScript with policy_id_hex and compiled_code_hex.
        """
        aiken  = cls._require_aiken()
        source = Path(source_blueprint_path)
        output = Path(output_blueprint_path)

        if not source.exists():
            raise AikenBlueprint.Error(f"Source blueprint not found: {source}")

        intermediate = output.with_suffix(output.suffix + ".step1")

        # Step 1: apply genesis_ref (first declared parameter)
        cls._run_apply(aiken, source, intermediate, genesis_ref.to_cbor_hex())

        # Step 2: apply beacon_asset_name (second declared parameter)
        beacon_cbor_hex = cbor2.dumps(beacon_asset_name).hex()
        cls._run_apply(aiken, intermediate, output, beacon_cbor_hex)

        try:
            intermediate.unlink()
        except OSError:
            pass

        try:
            blueprint = json.loads(output.read_text())
        except json.JSONDecodeError as e:
            raise AikenBlueprint.Error(f"Output blueprint is not valid JSON: {e}") from e

        spend_v = cls._find_validator(blueprint, cls.SPEND_TITLE)
        mint_v  = cls._find_validator(blueprint, cls.MINT_TITLE)

        if spend_v is None or mint_v is None:
            available = [v.get("title") for v in blueprint.get("validators", [])]
            raise AikenBlueprint.Error(
                f"Expected '{cls.SPEND_TITLE}' and '{cls.MINT_TITLE}' in output blueprint. "
                f"Available: {available}"
            )

        if spend_v["hash"] != mint_v["hash"]:
            raise AikenBlueprint.Error(
                f"spend hash ({spend_v['hash']}) and mint hash ({mint_v['hash']}) "
                f"differ after parameter application — expected identical."
            )

        return AikenBlueprint.AppliedScript(
            policy_id_hex=spend_v["hash"],
            compiled_code_hex=spend_v["compiledCode"],
            blueprint_path=output,
        )