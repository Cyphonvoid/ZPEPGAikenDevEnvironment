// validators/ArchiveRegistry.ak
use aiken/primitive/bytearray
use aiken/crypto.{VerificationKey, Signature, verify_ed25519_signature}
use cardano/address.{Address}
use cardano/transaction.{
  OutputReference, Transaction, Input, Output, Datum, InlineDatum, NoDatum, DatumHash,
}
use cardano/script_context.{ScriptContext}
use aiken/collection/list
// ── Master Registry Datum ───────────────────────────────────────────────
// Fixed size forever — no maps, no growing collections.

pub type MasterDatum {
  authority_key: VerificationKey,
  operator_key: VerificationKey,
  owner_key: VerificationKey,
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
  current_authority_key: VerificationKey,
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
    new_key: VerificationKey,
    signature: Signature,
  }
  LinkDeployment {
    nonce: Int,
    next_script_address: ByteArray,
    next_policy_id: ByteArray,
    next_authority_key: VerificationKey,
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

// ── Helpers ────────────────────────────────────────────────────────────

fn find_master_input(inputs: List<Input>, own_ref: OutputReference) -> Output {
  expect Some(input) =
    list.find(inputs, fn(i) { i.output_reference == own_ref })
  input.output
}

fn find_master_output(
  outputs: List<Output>,
  registry_address: Address,
) -> Output {
  expect Some(output) =
    list.find(outputs, fn(o) { o.address == registry_address })
  output
}

fn datum_from_output(output: Output) -> MasterDatum {
  expect InlineDatum(datum_data) = output.datum
  expect master_datum: MasterDatum = datum_data
  master_datum
}

// ── Spend Validator ────────────────────────────────────────────────────

validator archive_registry {
  spend(
    datum: Option<MasterDatum>,
    redeemer: RegistryAction,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(old_datum) = datum

    when redeemer is {
      MintDocument { nonce, global_identifier, version, signature } -> {
        // 1. Nonce must match current state exactly
        expect nonce == old_datum.nonce

        // 2. Registry must not be paused
        expect old_datum.is_paused == False

        // 3. Signature must be valid for operator_key over (nonce, global_identifier, version)
        let signed_payload =
          bytearray.concat(
            bytearray.concat(
              bytearray.from_int_big_endian(nonce, 8),
              global_identifier,
            ),
            bytearray.from_int_big_endian(version, 4),
          )
        expect verify_ed25519_signature(
          old_datum.operator_key,
          signed_payload,
          signature,
        )

        // 4. The new master UTXO output must exist at the same script address
        let master_input = find_master_input(self.inputs, own_ref)
        let new_output = find_master_output(self.outputs, master_input.address)
        let new_datum = datum_from_output(new_output)

        // 5. New datum must have nonce incremented by exactly 1
        expect new_datum.nonce == old_datum.nonce + 1

        // 6. All other fields must remain unchanged — no tampering
        expect new_datum.authority_key == old_datum.authority_key
        expect new_datum.operator_key == old_datum.operator_key
        expect new_datum.owner_key == old_datum.owner_key
        expect new_datum.owner_address == old_datum.owner_address
        expect new_datum.is_paused == old_datum.is_paused
        expect new_datum.policy_id == old_datum.policy_id
        expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
        expect new_datum.versions_utxo_ref == old_datum.versions_utxo_ref

        True
      }

      _ -> False
    }
  }
}