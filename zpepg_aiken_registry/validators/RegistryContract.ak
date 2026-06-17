// validators/ArchiveRegistry.ak

use aiken/crypto.{VerificationKeyHash, Signature}
use cardano/address.{Address}
use cardano/transaction.{OutputReference}

// ── Master Registry Datum ───────────────────────────────────────────────
// Fixed size forever — no maps, no growing collections.

pub type MasterDatum {
  authority_key: VerificationKeyHash,
  operator_key: VerificationKeyHash,
  owner_key: VerificationKeyHash,
  owner_address: Address,
  nonce: Int,
  is_paused: Bool,
  policy_id: ByteArray,
  asset_name_prefix: ByteArray,
  versions_utxo_ref: OutputReference,
  // Deployment chain — populated only when a chain link has been created.
  // Empty/zeroed when this deployment has not linked forward.
  chain_link: Option<DeploymentChainLink>,
}

// ── Deployment Chain Link ───────────────────────────────────────────────
// Two sections: human-readable pointer + cryptographic proof.

pub type DeploymentChainLink {
  // Section 1 — human-readable pointer
  next_script_address: ByteArray,
  next_policy_id: ByteArray,
  link_reason: ByteArray,
  linked_at: Int,
  instructions: ByteArray,
  // Section 2 — cryptographic proof
  current_authority_key: VerificationKeyHash,
  signature: Signature,
  nonce_at_link: Int,
}

// ── Token Datum (per minted document version) ───────────────────────────

pub type TokenDatum {
  global_identifier: ByteArray,
  sha256_hash: ByteArray,
  upload_date: ByteArray,
  version: Int,
  token_data: ByteArray,
  registry_address: ByteArray,
  policy_id: ByteArray,
}

// ── Versions Datum ───────────────────────────────────────────────────────
// sha256(global_id) -> ordered list of asset names, oldest to newest.

pub type VersionsDatum {
  document_chains: Pairs<ByteArray, List<ByteArray>>,
}

// ── Registry Action Redeemer ─────────────────────────────────────────────

pub type RegistryAction {
  MintDocument {
    nonce: Int,
    global_identifier: ByteArray,
    version: Int,
    signature: Signature,
  }
  Pause { nonce: Int, signature: Signature }
  Unpause { nonce: Int, signature: Signature }
  Withdraw { nonce: Int, amount: Int, signature: Signature }
  RotateKey {
    nonce: Int,
    key_type: KeyType,
    new_key: VerificationKeyHash,
    signature: Signature,
  }
  LinkDeployment {
    nonce: Int,
    next_script_address: ByteArray,
    next_policy_id: ByteArray,
    next_authority_key: VerificationKeyHash,
    link_reason: ByteArray,
    signature: Signature,
  }
}

pub type KeyType {
  AuthorityKey
  OperatorKey
  OwnerKey
}

// ── Mint Policy Redeemer ─────────────────────────────────────────────────

pub type MintAction {
  Mint
  Burn
}