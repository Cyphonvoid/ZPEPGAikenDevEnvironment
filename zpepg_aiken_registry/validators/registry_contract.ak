// validators/ArchiveRegistry.ak
use cardano/assets
use aiken/collection/dict
use aiken/primitive/bytearray
use aiken/crypto.{VerificationKey, Signature, verify_ed25519_signature}
use cardano/address.{Address, Credential, Script}
use cardano/transaction.{
  OutputReference, Transaction, TransactionId, Input, Output, Datum, InlineDatum, NoDatum, DatumHash,
}
use cardano/script_context.{ScriptContext}
use aiken/collection/list

// ── Master Registry Datum ───────────────────────────────────────────────
// Fixed size forever — no maps, no growing collections.
// Version history is reconstructible off-chain by querying all assets under
// policy_id and grouping/sorting by the UUID + version byte in the asset name.
//
// self_ref: the OutputReference of this very UTXO on-chain.
// Every transaction must verify own_ref == old_datum.self_ref (proving the
// correct canonical Master UTXO is being spent) and must write the new
// output's reference into new_datum.self_ref (rolling it forward).
// This prevents anyone from substituting a fake or stale Master UTXO.

pub type MasterDatum {
  authority_key: VerificationKey,
  operator_key: VerificationKey,
  owner_key: VerificationKey,
  owner_address: Address,
  nonce: Int,
  is_paused: Bool,
  policy_id: ByteArray,
  asset_name_prefix: ByteArray,
  self_ref: OutputReference,
  // Deployment chain — populated only when a chain link has been created.
  // None until LinkDeployment is called; set exactly once, never changed after.
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

// ── Registry Action Redeemer ─────────────────────────────────────────────

pub type RegistryAction {
  MintDocument {
    nonce: Int,
    global_identifier: ByteArray,
    version: Int,
    signature: Signature,
  }
  Pause { nonce: Int, signature: Signature }
  Resume { nonce: Int, signature: Signature }
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

pub type CreateTokenAction {
  MintToken
  BurnToken
}

// ── Helpers ────────────────────────────────────────────────────────────

fn find_master_input(inputs: List<Input>, own_ref: OutputReference) -> Output {
  expect Some(input) =
    list.find(inputs, fn(i) { i.output_reference == own_ref })
  input.output
}

// Finds the new Master UTXO output and returns it paired with its index
// in the outputs list. The index is needed to construct the new self_ref.
fn find_master_output_with_index(
  outputs: List<Output>,
  registry_address: Address,
) -> (Output, Int) {
  find_output_with_index_loop(outputs, registry_address, 0)
}

fn find_output_with_index_loop(
  outputs: List<Output>,
  registry_address: Address,
  index: Int,
) -> (Output, Int) {
  when outputs is {
    [] -> fail @"Master output not found at script address"
    [head, ..tail] ->
      if head.address == registry_address {
        (head, index)
      } else {
        find_output_with_index_loop(tail, registry_address, index + 1)
      }
  }
}

fn datum_from_output(output: Output) -> MasterDatum {
  expect InlineDatum(datum_data) = output.datum
  expect master_datum: MasterDatum = datum_data
  master_datum
}

// Constructs the OutputReference for a new output produced by this transaction.
// tx_id is self.id (the current transaction's hash).
// output_index is the position of the output in self.outputs (0-based).
fn make_output_ref(tx_id: TransactionId, output_index: Int) -> OutputReference {
  OutputReference { transaction_id: tx_id, output_index }
}

// ── Canonical Master UTXO check ────────────────────────────────────────
// Called at the top of every spend branch.
// Verifies that the UTXO currently being spent is the canonical Master UTXO
// by checking own_ref (injected by Cardano) against self_ref stored in the datum.
// Any fake, stale, or wrong-deployment UTXO will have a mismatched self_ref
// and will be rejected here before any other logic runs.

fn verify_canonical_master(own_ref: OutputReference, datum: MasterDatum) {
  expect own_ref == datum.self_ref
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

    // ── Canonical master UTXO check — runs before every branch ──────────
    // Proves the UTXO being spent is the real canonical Master UTXO.
    // Rejects any fake, stale, or wrong-deployment substitution attempt.
    verify_canonical_master(own_ref, old_datum)

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

        // 4. Find the new master UTXO output and its index
        let master_input = find_master_input(self.inputs, own_ref)
        let (new_output, new_output_index) =
          find_master_output_with_index(self.outputs, master_input.address)
        let new_datum = datum_from_output(new_output)

        // 5. New datum must have nonce incremented by exactly 1
        expect new_datum.nonce == old_datum.nonce + 1

        // 6. self_ref must be updated to point to the new output's reference
        expect new_datum.self_ref == make_output_ref(self.id, new_output_index)

        // 7. All other fields must remain unchanged — no tampering
        expect new_datum.authority_key == old_datum.authority_key
        expect new_datum.operator_key == old_datum.operator_key
        expect new_datum.owner_key == old_datum.owner_key
        expect new_datum.owner_address == old_datum.owner_address
        expect new_datum.is_paused == old_datum.is_paused
        expect new_datum.policy_id == old_datum.policy_id
        expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
        expect new_datum.chain_link == old_datum.chain_link

        True
      }

      Pause { nonce, signature } -> {
        // 1. Nonce must match current state exactly
        expect nonce == old_datum.nonce

        // 2. Signature must be valid for authority_key over (nonce, "PAUSE")
        let signed_payload =
          bytearray.concat(
            bytearray.from_int_big_endian(nonce, 8),
            "PAUSE",
          )
        expect verify_ed25519_signature(
          old_datum.authority_key,
          signed_payload,
          signature,
        )

        // 3. Find the new master UTXO output and its index
        let master_input = find_master_input(self.inputs, own_ref)
        let (new_output, new_output_index) =
          find_master_output_with_index(self.outputs, master_input.address)
        let new_datum = datum_from_output(new_output)

        // 4. Nonce must increment by exactly 1
        expect new_datum.nonce == old_datum.nonce + 1

        // 5. is_paused must flip to True
        expect new_datum.is_paused == True

        // 6. self_ref must be updated to point to the new output's reference
        expect new_datum.self_ref == make_output_ref(self.id, new_output_index)

        // 7. All other fields must remain unchanged
        expect new_datum.authority_key == old_datum.authority_key
        expect new_datum.operator_key == old_datum.operator_key
        expect new_datum.owner_key == old_datum.owner_key
        expect new_datum.owner_address == old_datum.owner_address
        expect new_datum.policy_id == old_datum.policy_id
        expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
        expect new_datum.chain_link == old_datum.chain_link

        True
      }

      Resume { nonce, signature } -> {
        // 1. Nonce must match current state exactly
        expect nonce == old_datum.nonce

        // 2. Signature must be valid for authority_key over (nonce, "RESUME")
        let signed_payload =
          bytearray.concat(
            bytearray.from_int_big_endian(nonce, 8),
            "RESUME",
          )
        expect verify_ed25519_signature(
          old_datum.authority_key,
          signed_payload,
          signature,
        )


        // 3. Find the new master UTXO output and its index
        let master_input = find_master_input(self.inputs, own_ref)
        let (new_output, new_output_index) =
          find_master_output_with_index(self.outputs, master_input.address)
        let new_datum = datum_from_output(new_output)

        // 4. Nonce must increment by exactly 1
        expect new_datum.nonce == old_datum.nonce + 1

        // 5. is_paused must flip to False
        expect new_datum.is_paused == False

        // 6. self_ref must be updated to point to the new output's reference
        expect new_datum.self_ref == make_output_ref(self.id, new_output_index)

        // 7. All other fields must remain unchanged
        expect new_datum.authority_key == old_datum.authority_key
        expect new_datum.operator_key == old_datum.operator_key
        expect new_datum.owner_key == old_datum.owner_key
        expect new_datum.owner_address == old_datum.owner_address
        expect new_datum.policy_id == old_datum.policy_id
        expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
        expect new_datum.chain_link == old_datum.chain_link

        True
      }

      Withdraw { nonce, amount, signature } -> {
        // 1. Nonce must match current state exactly
        expect nonce == old_datum.nonce

        // 2. Signature must be valid for owner_key over (nonce, "WITHDRAW", amount)
        let signed_payload =
          bytearray.concat(
            bytearray.concat(
              bytearray.from_int_big_endian(nonce, 8),
              "WITHDRAW",
            ),
            bytearray.from_int_big_endian(amount, 8),
          )
        expect verify_ed25519_signature(
          old_datum.owner_key,
          signed_payload,
          signature,
        )

        // 3. Find the new master UTXO output and its index
        let master_input = find_master_input(self.inputs, own_ref)
        let (new_output, new_output_index) =
          find_master_output_with_index(self.outputs, master_input.address)
        let new_datum = datum_from_output(new_output)

        // 4. Nonce must increment by exactly 1
        expect new_datum.nonce == old_datum.nonce + 1

        // 5. The withdrawn amount must actually go to owner_address
        let withdrawal_output =
          list.any(
            self.outputs,
            fn(o) {
              o.address == old_datum.owner_address && assets.lovelace_of(
                o.value,
              ) == amount
            },
          )
        expect withdrawal_output == True

        // 6. self_ref must be updated to point to the new output's reference
        expect new_datum.self_ref == make_output_ref(self.id, new_output_index)

        // 7. All datum fields must remain unchanged (withdraw doesn't alter state besides nonce)
        expect new_datum.authority_key == old_datum.authority_key
        expect new_datum.operator_key == old_datum.operator_key
        expect new_datum.owner_key == old_datum.owner_key
        expect new_datum.owner_address == old_datum.owner_address
        expect new_datum.is_paused == old_datum.is_paused
        expect new_datum.policy_id == old_datum.policy_id
        expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
        expect new_datum.chain_link == old_datum.chain_link

        True
      }

      RotateKey { nonce, key_type, new_key, signature } -> {
        // 1. Nonce must match current state exactly
        expect nonce == old_datum.nonce

        // 2. Build a byte tag for which key type is being rotated, for the signed payload
        let key_type_tag =
          when key_type is {
            AuthorityKey -> "AUTHORITY"
            OperatorKey -> "OPERATOR"
            OwnerKey -> "OWNER"
          }

        // 3. Signature must be valid for authority_key over (nonce, "ROTATE", key_type_tag, new_key)
        let signed_payload =
          bytearray.concat(
            bytearray.concat(
              bytearray.concat(
                bytearray.from_int_big_endian(nonce, 8),
                "ROTATE",
              ),
              key_type_tag,
            ),
            new_key,
          )
        expect verify_ed25519_signature(
          old_datum.authority_key,
          signed_payload,
          signature,
        )

        // 4. Find the new master UTXO output and its index
        let master_input = find_master_input(self.inputs, own_ref)
        let (new_output, new_output_index) =
          find_master_output_with_index(self.outputs, master_input.address)
        let new_datum = datum_from_output(new_output)

        // 5. Nonce must increment by exactly 1
        expect new_datum.nonce == old_datum.nonce + 1

        // 6. Exactly the targeted key field changes to new_key; all others stay identical
        when key_type is {
          AuthorityKey -> {
            expect new_datum.authority_key == new_key
            expect new_datum.operator_key == old_datum.operator_key
            expect new_datum.owner_key == old_datum.owner_key
          }
          OperatorKey -> {
            expect new_datum.authority_key == old_datum.authority_key
            expect new_datum.operator_key == new_key
            expect new_datum.owner_key == old_datum.owner_key
          }
          OwnerKey -> {
            expect new_datum.authority_key == old_datum.authority_key
            expect new_datum.operator_key == old_datum.operator_key
            expect new_datum.owner_key == new_key
          }
        }

        // 7. self_ref must be updated to point to the new output's reference
        expect new_datum.self_ref == make_output_ref(self.id, new_output_index)

        // 8. Remaining fields must always stay unchanged
        expect new_datum.owner_address == old_datum.owner_address
        expect new_datum.is_paused == old_datum.is_paused
        expect new_datum.policy_id == old_datum.policy_id
        expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
        expect new_datum.chain_link == old_datum.chain_link

        True
      }

      LinkDeployment {
        nonce,
        next_script_address,
        next_policy_id,
        next_authority_key,
        link_reason,
        signature,
      } -> {
        // 1. Nonce must match current state exactly
        expect nonce == old_datum.nonce

        // 2. A deployment chain link can only be created once per deployment —
        //    this deployment must not already have linked forward
        expect old_datum.chain_link == None

        // 3. Signature must be valid for authority_key over a payload binding
        //    the next deployment's full identity plus the nonce
        let signed_payload =
          bytearray.concat(
            bytearray.concat(
              bytearray.concat(
                bytearray.from_int_big_endian(nonce, 8),
                next_policy_id,
              ),
              next_script_address,
            ),
            next_authority_key,
          )
        expect verify_ed25519_signature(
          old_datum.authority_key,
          signed_payload,
          signature,
        )

        // 4. Find the new master UTXO output and its index
        let master_input = find_master_input(self.inputs, own_ref)
        let (new_output, new_output_index) =
          find_master_output_with_index(self.outputs, master_input.address)
        let new_datum = datum_from_output(new_output)

        // 5. Nonce must increment by exactly 1
        expect new_datum.nonce == old_datum.nonce + 1

        // 6. The new datum's chain_link must contain the correct pointer and proof
        expect Some(link) = new_datum.chain_link
        expect link.next_script_address == next_script_address
        expect link.next_policy_id == next_policy_id
        expect link.link_reason == link_reason
        expect link.current_authority_key == old_datum.authority_key
        expect link.signature == signature
        expect link.nonce_at_link == nonce

        // 7. self_ref must be updated to point to the new output's reference
        expect new_datum.self_ref == make_output_ref(self.id, new_output_index)

        // 8. All other fields must remain unchanged
        expect new_datum.authority_key == old_datum.authority_key
        expect new_datum.operator_key == old_datum.operator_key
        expect new_datum.owner_key == old_datum.owner_key
        expect new_datum.owner_address == old_datum.owner_address
        expect new_datum.is_paused == old_datum.is_paused
        expect new_datum.policy_id == old_datum.policy_id
        expect new_datum.asset_name_prefix == old_datum.asset_name_prefix

        True
      }
    }
  }

  mint(token_action: CreateTokenAction, policy_id: ByteArray, self: Transaction) {
    when token_action is {

      MintToken -> {
        // 1. Exactly one token must be minted under this policy
        let minted_assets = assets.tokens(self.mint, policy_id)
        expect [Pair(asset_name, quantity)] = dict.to_pairs(minted_assets)
        expect quantity == 1

        // 2. Master UTXO must be present as an input in this transaction —
        //    proves spend validator already enforced nonce/signature/pause/self_ref
        expect Some(master_input) =
          list.find(
            self.inputs,
            fn(i) { i.output.address.payment_credential == Script(policy_id) },
          )

        // 3. The master UTXO's datum must be a valid MasterDatum we can read
        expect InlineDatum(datum_data) = master_input.output.datum
        expect master_datum: MasterDatum = datum_data

        // 4. Asset name must match our naming scheme prefix
        let prefix = master_datum.asset_name_prefix
        let prefix_len = bytearray.length(prefix)
        expect bytearray.take(asset_name, prefix_len) == prefix

        True
      }

      BurnToken -> {
        // Token is immutable, non burnable, unerasable. Explicitly disallowed by design.
        False
      }
    }
  }
}
