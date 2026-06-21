"""
PlutusData mirrors of the on-chain types defined in archive_registry.ak
and beacon_contract.ak. These MUST stay byte-for-byte structurally
identical to the Aiken types (same field order, same CONSTR_ID per
variant) or datum/redeemer encoding will silently mismatch what the
validator expects.

IMPORTANT - Bool and Option<T> are NOT plain Python bool/None:
A bare Python `None` or `bool` field on a dataclass PlutusData encodes
as raw CBOR nil/bool primitives, which does NOT match what Aiken's
compiled validator expects to decode (it expects tagged constructors).
So every Bool and Option<T> field below uses explicit constructor
classes instead of native Python types.

Constructor indices below are VERIFIED directly against this project's
own compiled plutus.json (definitions.Bool, definitions.Option<...>),
not inferred from prose documentation:
    Bool:      False = Constr 0 [],  True = Constr 1 []
    Option<T>: Some(x) = Constr 0 [x],  None = Constr 1 []

IMPORTANT - field type annotations cannot be bare `object`:
PyCardano's PlutusData.__post_init__ validates each field's declared
type against a fixed allow-list (PlutusData subclasses, dict,
IndefiniteList, int, ByteString, bytes) and raises TypeError on
anything else, including a bare `object` annotation used as a
"could be one of several types" placeholder. Every polymorphic field
below uses an explicit typing.Union of concrete PlutusData subclasses
instead. Because Option<T> wraps different concrete types in different
places in our schema (DeploymentChainLink in MasterDatum's links,
InlineStakeCredential in Address), we define ONE distinct Some/Option
class PER wrapped type, rather than a single generic Some - this keeps
every field's Union resolvable without forward-reference tricks, at
the cost of a little repetition.
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
# VerificationKey(hash) = Constr 0 [hash], Script(hash) = Constr 1 [hash]
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
# Inline(Credential) = Constr 0 [Credential], Pointer(...) = Constr 1 [...]
# VERIFIED against compiled plutus.json definitions.cardano/address/StakeCredential
# (only Inline is implemented here - Pointer addresses aren't used by ZPEPG)
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
# Single constructor (index 0), fields: payment_credential, stake_credential
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