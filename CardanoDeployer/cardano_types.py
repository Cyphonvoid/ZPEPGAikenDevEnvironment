"""
cardano_types.py - On-chain Plutus type mirrors for ZPEPG registry contract.

PlutusData subclasses mirroring registry_contract.ak's `validator
archive_registry`. CONSTR_ID values and field ordering are VERIFIED
against compiled plutus.json. These must stay structurally identical to
the Aiken types or datum/redeemer encoding will silently mismatch what
the validator expects.

SINGLE-SCRIPT ARCHITECTURE NOTE: beacon_contract.ak / beacon_policy.ak no
longer exist as separate files. The one-shot beacon mint is now the
MintBeacon variant of registry_contract.ak's own CreateTokenAction (mint
redeemer), declared in the same file as MintToken/BurnToken. MintBeacon's
CONSTR_ID is therefore 2 here (declaration order: MintToken=0, BurnToken=1,
MintBeacon=2), NOT 0 as it was when beacon_policy.ak was a standalone
single-variant redeemer type. Getting this wrong produces the exact class
of silent on-chain rejection (wrong constructor index) that cost an entire
debugging session earlier in this project - if MintBeacon ever fails val-
idation unexpectedly, this is the first thing to re-verify against the
actual compiled plutus.json.
"""

from dataclasses import dataclass
from typing import Union
from pycardano import PlutusData


# ── cardano/transaction.OutputReference ───────────────────────────────────
@dataclass
class OutputReference(PlutusData):
    CONSTR_ID = 0
    transaction_id: bytes
    output_index: int


# ── Aiken Bool ─────────────────────────────────────────────────────────────
# VERIFIED: False = Constr 0 [], True = Constr 1 []
@dataclass
class AikenFalse(PlutusData):
    CONSTR_ID = 0

@dataclass
class AikenTrue(PlutusData):
    CONSTR_ID = 1

AikenBool = Union[AikenFalse, AikenTrue]

def aiken_bool(value: bool) -> AikenBool:
    return AikenTrue() if value else AikenFalse()


# ── registry_contract.DeploymentChainLink ─────────────────────────────────
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


# ── Option<DeploymentChainLink> ───────────────────────────────────────────
# VERIFIED: Some(x) = Constr 0 [x], None = Constr 1 []
@dataclass
class SomeChainLink(PlutusData):
    CONSTR_ID = 0
    value: DeploymentChainLink

@dataclass
class NoneChainLink(PlutusData):
    CONSTR_ID = 1

OptionChainLink = Union[SomeChainLink, NoneChainLink]


# ── registry_contract.RegistryStats ───────────────────────────────────────
@dataclass
class RegistryStats(PlutusData):
    CONSTR_ID = 0
    total_token_count: int
    total_unique_documents: int
    last_minted_at: int
    last_cross_chain_global_id: bytes
    last_cardano_asset_id: bytes


# ── cardano/address.Credential ─────────────────────────────────────────────
# VERIFIED against compiled plutus.json definitions.cardano/address/Credential
@dataclass
class VerificationKeyCredential(PlutusData):
    CONSTR_ID = 0
    credential_hash: bytes

@dataclass
class ScriptCredential(PlutusData):
    CONSTR_ID = 1
    credential_hash: bytes

Credential = Union[VerificationKeyCredential, ScriptCredential]


# ── cardano/address.StakeCredential ───────────────────────────────────────
# VERIFIED against compiled plutus.json definitions.cardano/address/StakeCredential
@dataclass
class InlineStakeCredential(PlutusData):
    CONSTR_ID = 0
    credential: Credential


# ── Option<StakeCredential> ───────────────────────────────────────────────
@dataclass
class SomeStakeCredential(PlutusData):
    CONSTR_ID = 0
    value: InlineStakeCredential

@dataclass
class NoneStakeCredential(PlutusData):
    CONSTR_ID = 1

OptionStakeCredential = Union[SomeStakeCredential, NoneStakeCredential]


# ── cardano/address.Address ───────────────────────────────────────────────
# VERIFIED against compiled plutus.json definitions.cardano/address/Address
@dataclass
class PlutusAddress(PlutusData):
    CONSTR_ID = 0
    payment_credential: Credential
    stake_credential: OptionStakeCredential


# ── registry_contract.MasterDatum ─────────────────────────────────────────
# CHANGED (single-script merge): beacon_policy_id / beacon_asset_name are
# NO LONGER fields here. "What counts as the beacon" is now a compile-time
# fact baked into the validator's own parameters (genesis_ref,
# beacon_asset_name), never something read out of a datum - see
# registry_contract.ak's header comment for the full rationale. Field
# count dropped from 13 to 11; every downstream construction site (genesis
# bootstrap, every test redeemer/datum builder) must be updated to match,
# or this will silently produce the exact field-shift class of bug this
# project already debugged once today.
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


# ── registry_contract.CreateTokenAction (mint redeemer) ───────────────────
# pub type CreateTokenAction { MintToken BurnToken MintBeacon }
# Declaration order -> CONSTR_ID: MintToken=0, BurnToken=1, MintBeacon=2
#
# MintBeacon lives here (not in test_types.py) because the DEPLOYER needs
# to construct it for the genesis transaction - cardano_workflow.py has no
# dependency on test_types.py (a test-only file) and shouldn't gain one.
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