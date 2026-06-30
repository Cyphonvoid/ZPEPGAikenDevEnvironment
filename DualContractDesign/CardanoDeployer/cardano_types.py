"""
cardano_types.py - On-chain Plutus type mirrors for ZPEPG registry contracts.

PlutusData subclasses mirroring archive_registry.ak and beacon_contract.ak.
CONSTR_ID values and field ordering are VERIFIED against compiled plutus.json.
These must stay structurally identical to the Aiken types or datum/redeemer
encoding will silently mismatch what the validator expects.
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
    beacon_policy_id: bytes
    beacon_asset_name: bytes
    forward_link: OptionChainLink
    backward_link: OptionChainLink
    stats: RegistryStats


# ── beacon_contract.BeaconAction ──────────────────────────────────────────
@dataclass
class MintBeacon(PlutusData):
    CONSTR_ID = 0
