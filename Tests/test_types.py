"""
test_types.py - Test-only PlutusData type extensions.

Lives at the project ROOT, separate from CardanoDeployer/cardano_types.py
on purpose: the deployer package only ever needed what genesis bootstrap
used (MasterDatum, MintBeacon, the Address/Credential/Option/Bool helpers).
It never needed TokenDatum, RegistryAction, or CreateTokenAction, since the
deployer never spends the registry contract - only the test suite does.

Imports the shared base types (OutputReference, AikenBool/True/False,
MasterDatum, etc.) from CardanoDeployer.cardano_types rather than
redefining them, so there is exactly one source of truth for each shared
type.

CONSTR_ID assignment follows the established pattern in this project:
declaration order within the Aiken `pub type X { A B C }` block determines
constructor index, starting at 0. Verified directly against the compiled
plutus.json's definitions for registry_contract/RegistryAction (all 7
variants, field order, and field types matched exactly on inspection).
KeyType, CreateTokenAction, and TokenDatum follow the same Aiken
declaration-order convention but were not independently re-verified
against plutus.json the same way - if anything here ever produces an
unexpected on-chain rejection, check these first.
"""

from dataclasses import dataclass
from typing import Union

from pycardano import PlutusData

from CardanoDeployer.cardano_types import OutputReference, AikenBool


# ── registry_contract.TokenDatum ──────────────────────────────────────────
# Field order matches the .ak declaration exactly:
#   cardano_asset_id, cross_chain_global_id, registry_address, policy_id,
#   source_registry_master_utxo_reference, sha256_hash, upload_date,
#   version, token_data

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


# ── registry_contract.KeyType ─────────────────────────────────────────────
# pub type KeyType { AuthorityKey OperatorKey OwnerKey }
# Declaration order -> CONSTR_ID: AuthorityKey=0, OperatorKey=1, OwnerKey=2

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


# ── registry_contract.RegistryAction ──────────────────────────────────────
# Declaration order in the .ak file (confirmed from the pasted source):
#   MintDocument=0, Pause=1, Resume=2, Withdraw=3, RotateKey=4,
#   LinkForward=5, LinkBackward=6

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


# ── registry_contract.CreateTokenAction (mint redeemer) ───────────────────
# pub type CreateTokenAction { MintToken BurnToken }
# Declaration order -> CONSTR_ID: MintToken=0, BurnToken=1

@dataclass
class MintToken(PlutusData):
    CONSTR_ID = 0


@dataclass
class BurnToken(PlutusData):
    CONSTR_ID = 1


CreateTokenAction = Union[MintToken, BurnToken]