// =============================================================================
// CONTRACT NAME: ArchiveRegistry
// PURPOSE: A decentralized, immutable document metadata registry and native 
//          token asset issuance contract built on Cardano's eUTXO model.
//
// SYSTEM OVERVIEW:
// This contract maintains a single, highly protected "Master Registry" UTXO 
// that tracks system configurations, operational nonces, and running state 
// metrics. In tandem, it governs a dedicated Minting Policy used to issue 
// unique native asset tokens representing individual registered documents 
// and their associated metadata payloads.
//
// ── CARDANO SECURITY & ACCESS CONTROL HIERARCHY
// The contract enforces a strict, multi-tiered cryptographic signature framework 
// using public key hashes stored inside the active registry state:
//   - Authority Key: The root system administrator. Exclusively authorized to 
//     pause/resume operations, rotate keys, and establish deployment linkages.
//   - Operator Key: A worker identity optimized for automated backends and 
//     burner accounts. It is wallet-agnostic and only permitted to mint documents.
//   - Owner Key/Address: The vault identity restricted entirely to signing off 
//     on fund withdrawals, ensuring assets can only exit to a hardcoded destination.
//
// =============================================================================
// CORE FUNCTIONALITIES AND KEY FEATURES:
//
// 1. STATE-TRACKING & METRICS SYSTEM
//    Maintains a continuous, live `RegistryStats` block that securely records 
//    the running health of the archive, including total issued token counts, 
//    unique document tallies, timestamps of the last minting activity, and 
//    the identifiers of the most recently generated asset.
//
// 2. ATOMIC DOCUMENT MINTING (`MintDocument` / `MintToken`)
//    Handles coordinated validation between the spend and mint validators. It 
//    permits document creation only if signed by the operator, matching the 
//    state nonce, and ensures the accompanying token output embeds a structured, 
//    tamper-proof metadata payload (SHA256 hash, version number, data bytes).
//
// 3. CIRCUIT-BREAKER LIFECYCLE CONTROLS (`Pause` / `Resume`)
//    Enables the primary authority to immediately freeze all minting behaviors 
//    if unexpected conditions arise, providing a secure runtime switch to halt 
//    the script's core operations without risking registry state corruption.
//
// 4. SECURE REVENUE MANAGEMENT (`Withdraw`)
//    Implements an locked withdrawal gate requiring an explicit cryptographic 
//    signature from the designated Owner Key. It strictly validates that any 
//    withdrawn Lovelace matching the requested amount is paid out directly to 
//    the unchangeable `owner_address` stored in the contract.
//
// 5. ADMINISTRATIVE MAINTENANCE (`RotateKey`)
//    Allows the root authority to cleanly migrate operational keys (Authority, 
//    Operator, or Owner) to new public key hashes dynamically, ensuring smooth 
//    rotation without altering code deployments.
//
// 6. BIDIRECTIONAL DEPLOYMENT CHAINING (`LinkForward` / `LinkBackward`)
//    Addresses smart contract immutability by providing a dual-pointer system 
//    to migrate or trace older and newer versions of the contract architecture:
//      - `LinkForward`: Permanent pointer sealing a current registry's path 
//        forward to its newly deployed successor script.
//      - `LinkBackward`: Permanent pointer allowing a new script to map its lineage 
//        backward to its historical ancestral origin.
//    Once written, these slots are permanently locked to establish an un-censorable, 
//    two-way cryptographic path of historical system custody on the blockchain.
// =============================================================================

use cardano/assets
use aiken/collection/dict
use aiken/primitive/bytearray
use aiken/crypto.{VerificationKey, Signature, verify_ed25519_signature}
use cardano/address.{Address, Script}
use cardano/transaction.{
  OutputReference, Transaction, TransactionId, Input, Output, InlineDatum,
}
use aiken/collection/list

// ── PILLAR 1: REGISTRY LEVEL ZID METRICS ─────────────────────────────────
pub type RegistryStats {
  total_token_count: Int,
  total_unique_documents: Int,
  last_minted_at: Int,
  last_cross_chain_global_id: ByteArray, 
  last_cardano_asset_id: ByteArray,      
}

// ── Master Registry Datum ────────────────────────────────────────────────
pub type MasterDatum {
  // ── REGISTRY ACCESS & CONFIGURATION ────────────────────────────────────
  authority_key: VerificationKey,
  operator_key: VerificationKey,
  owner_key: VerificationKey,
  owner_address: Address,
  nonce: Int,
  is_paused: Bool,
  
  // ── SYSTEM IDENTIFIERS & POINTERS ──────────────────────────────────────
  policy_id: ByteArray,
  asset_name_prefix: ByteArray,
  self_ref: OutputReference,
  
  // ── TWO-WAY DEPLOYMENT CHAIN LINKS ─────────────────────────────────────
  forward_link: Option<DeploymentChainLink>,
  backward_link: Option<DeploymentChainLink>,
  
  // ── STATS BLOCK ────────────────────────────────────────────────────────
  stats: RegistryStats,
}

// ── Deployment Chain Link Layout ──────────────────────────────────────────
pub type DeploymentChainLink {
  next_script_address: ByteArray,
  next_policy_id: ByteArray,
  link_reason: ByteArray,
  linked_at: Int,
  instructions: ByteArray,
  current_authority_key: VerificationKey,
  signature: Signature,
  nonce_at_link: Int,
}

// ── Token Datum (per minted document version) ────────────────────────────
pub type TokenDatum {
  // ── SECTION 1: PRIMARY ZID PURPOSES ────────────────────────────────────
  cardano_asset_id: ByteArray,
  cross_chain_global_id: ByteArray,

  // ── SECTION 2: SECONDARY ZID PURPOSES ──────────────────────────────────
  registry_address: ByteArray,
  policy_id: ByteArray,
  source_registry_master_utxo_reference: OutputReference,

  // ── SECTION 3: TOKEN DATUM CONTENTS (ARCHIVE PAYLOAD) ─────────────────
  sha256_hash: ByteArray,
  upload_date: ByteArray,
  version: Int,
  token_data: ByteArray,
}

// ── Registry Action Redeemer ─────────────────────────────────────────────
pub type RegistryAction {
  MintDocument {
    nonce: Int,
    cross_chain_global_id: ByteArray,
    sha256_hash: ByteArray,
    upload_date: ByteArray,
    version: Int,
    token_data: ByteArray,
    is_unique_document: Bool,
    valid_lower_bound: Int,
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
  LinkForward {
    nonce: Int,
    next_script_address: ByteArray,
    next_policy_id: ByteArray,
    link_reason: ByteArray,
    linked_at: Int,
    instructions: ByteArray,
    signature: Signature,
  }
  LinkBackward {
    nonce: Int,
    prev_script_address: ByteArray,
    prev_policy_id: ByteArray,
    link_reason: ByteArray,
    linked_at: Int,
    instructions: ByteArray,
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

// ── Helpers ──────────────────────────────────────────────────────────────

fn find_master_input(inputs: List<Input>, own_ref: OutputReference) -> Output {
  expect Some(input) =
    list.find(inputs, fn(i) { i.output_reference == own_ref })
  input.output
}

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

fn find_token_output_with_datum(outputs: List<Output>, policy_id: ByteArray) -> TokenDatum {
  when outputs is {
    [] -> fail @"Token output with inline TokenDatum not found"
    [head, ..tail] ->
      when head.datum is {
        InlineDatum(datum_data) -> {
          expect token_datum: TokenDatum = datum_data
          if token_datum.policy_id == policy_id {
            token_datum
          } else {
            find_token_output_with_datum(tail, policy_id)
          }
        }
        _ -> find_token_output_with_datum(tail, policy_id)
      }
  }
}

fn datum_from_output(output: Output) -> MasterDatum {
  expect InlineDatum(datum_data) = output.datum
  expect master_datum: MasterDatum = datum_data
  master_datum
}

fn make_output_ref(tx_id: TransactionId, output_index: Int) -> OutputReference {
  OutputReference { transaction_id: tx_id, output_index }
}

fn verify_canonical_master(own_ref: OutputReference, datum: MasterDatum) {
  expect own_ref == datum.self_ref
}

// ── Spend Validator ──────────────────────────────────────────────────────

validator archive_registry {

  spend(
    datum: Option<MasterDatum>,
    redeemer: RegistryAction,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(old_datum) = datum

    // ── Canonical master UTXO check — runs before every branch ───────────
    verify_canonical_master(own_ref, old_datum)

    when redeemer is {
      MintDocument { 
        nonce, 
        cross_chain_global_id, 
        sha256_hash, 
        upload_date, 
        version, 
        token_data, 
        is_unique_document,
        valid_lower_bound,
        signature 
      } -> {
        expect nonce == old_datum.nonce
        expect old_datum.is_paused == False

        let signed_payload =
          bytearray.concat(
            bytearray.concat(
              bytearray.concat(
                bytearray.from_int_big_endian(nonce, 8),
                cross_chain_global_id,
              ),
              sha256_hash,
            ),
            bytearray.from_int_big_endian(version, 4),
          )
         
        expect verify_ed25519_signature(
          old_datum.operator_key,
          signed_payload,
          signature,
        )

        let master_input = find_master_input(self.inputs, own_ref)
        let (new_output, new_output_index) =
          find_master_output_with_index(self.outputs, master_input.address)
        let new_datum = datum_from_output(new_output)

        let token_output_datum = find_token_output_with_datum(self.outputs, old_datum.policy_id)

        // Validate Token Setup (Pillar 2 Extensions)
        expect token_output_datum.cross_chain_global_id == cross_chain_global_id
        expect token_output_datum.registry_address == #"" 
        expect token_output_datum.policy_id == old_datum.policy_id
        expect token_output_datum.source_registry_master_utxo_reference == own_ref
        
        // Payload Verification (Section 3 Integrity Check)
        expect token_output_datum.sha256_hash == sha256_hash
        expect token_output_datum.upload_date == upload_date
        expect token_output_datum.version == version
        expect token_output_datum.token_data == token_data

        // Validate Master Registry Updates (Pillar 1 Upgrades)
        expect new_datum.nonce == old_datum.nonce + 1
        expect new_datum.self_ref == make_output_ref(self.id, new_output_index)
        
        expect new_datum.stats.total_token_count == old_datum.stats.total_token_count + 1
        
        let expected_unique_inc = if is_unique_document { 1 } else { 0 }
        expect new_datum.stats.total_unique_documents == old_datum.stats.total_unique_documents + expected_unique_inc
        expect new_datum.stats.last_minted_at == valid_lower_bound
        expect new_datum.stats.last_cross_chain_global_id == cross_chain_global_id
        expect new_datum.stats.last_cardano_asset_id == token_output_datum.cardano_asset_id

        // Static fields preserved
        expect new_datum.authority_key == old_datum.authority_key
        expect new_datum.operator_key == old_datum.operator_key
        expect new_datum.owner_key == old_datum.owner_key
        expect new_datum.owner_address == old_datum.owner_address
        expect new_datum.is_paused == old_datum.is_paused
        expect new_datum.policy_id == old_datum.policy_id
        expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
        expect new_datum.forward_link == old_datum.forward_link
        expect new_datum.backward_link == old_datum.backward_link

        True
      }

      Pause { nonce, signature } -> {
        expect nonce == old_datum.nonce
        let signed_payload =
          bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "PAUSE")
        expect verify_ed25519_signature(old_datum.authority_key, signed_payload, signature)

        let master_input = find_master_input(self.inputs, own_ref)
        let (new_output, new_output_index) = find_master_output_with_index(self.outputs, master_input.address)
        let new_datum = datum_from_output(new_output)

        expect new_datum.nonce == old_datum.nonce + 1
        expect new_datum.is_paused == True
        expect new_datum.self_ref == make_output_ref(self.id, new_output_index)

        expect new_datum.stats == old_datum.stats
        expect new_datum.authority_key == old_datum.authority_key
        expect new_datum.operator_key == old_datum.operator_key
        expect new_datum.owner_key == old_datum.owner_key
        expect new_datum.owner_address == old_datum.owner_address
        expect new_datum.policy_id == old_datum.policy_id
        expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
        expect new_datum.forward_link == old_datum.forward_link
        expect new_datum.backward_link == old_datum.backward_link

        True
      }

      Resume { nonce, signature } -> {
        expect nonce == old_datum.nonce
        let signed_payload =
          bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "RESUME")
        expect verify_ed25519_signature(old_datum.authority_key, signed_payload, signature)

        let master_input = find_master_input(self.inputs, own_ref)
        let (new_output, new_output_index) = find_master_output_with_index(self.outputs, master_input.address)
        let new_datum = datum_from_output(new_output)

        expect new_datum.nonce == old_datum.nonce + 1
        expect new_datum.is_paused == False
        expect new_datum.self_ref == make_output_ref(self.id, new_output_index)

        expect new_datum.stats == old_datum.stats
        expect new_datum.authority_key == old_datum.authority_key
        expect new_datum.operator_key == old_datum.operator_key
        expect new_datum.owner_key == old_datum.owner_key
        expect new_datum.owner_address == old_datum.owner_address
        expect new_datum.policy_id == old_datum.policy_id
        expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
        expect new_datum.forward_link == old_datum.forward_link
        expect new_datum.backward_link == old_datum.backward_link

        True
      }

      Withdraw { nonce, amount, signature } -> {
        expect nonce == old_datum.nonce
        let signed_payload =
          bytearray.concat(
            bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "WITHDRAW"),
            bytearray.from_int_big_endian(amount, 8),
          )
        expect verify_ed25519_signature(old_datum.owner_key, signed_payload, signature)

        let master_input = find_master_input(self.inputs, own_ref)
        let (new_output, new_output_index) = find_master_output_with_index(self.outputs, master_input.address)
        let new_datum = datum_from_output(new_output)

        expect new_datum.nonce == old_datum.nonce + 1
        expect new_datum.self_ref == make_output_ref(self.id, new_output_index)

        let withdrawal_output =
          list.any(self.outputs, fn(o) { o.address == old_datum.owner_address && assets.lovelace_of(o.value) == amount })
        expect withdrawal_output == True

        expect new_datum.stats == old_datum.stats
        expect new_datum.authority_key == old_datum.authority_key
        expect new_datum.operator_key == old_datum.operator_key
        expect new_datum.owner_key == old_datum.owner_key
        expect new_datum.owner_address == old_datum.owner_address
        expect new_datum.is_paused == old_datum.is_paused
        expect new_datum.policy_id == old_datum.policy_id
        expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
        expect new_datum.forward_link == old_datum.forward_link
        expect new_datum.backward_link == old_datum.backward_link

        True
      }

      RotateKey { nonce, key_type, new_key, signature } -> {
        expect nonce == old_datum.nonce
        let key_type_tag =
          when key_type is {
            AuthorityKey -> "AUTHORITY"
            OperatorKey -> "OPERATOR"
            OwnerKey -> "OWNER"
          }

        let signed_payload =
          bytearray.concat(
            bytearray.concat(
              bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "ROTATE"),
              key_type_tag,
            ),
            new_key,
          )
        expect verify_ed25519_signature(old_datum.authority_key, signed_payload, signature)

        let master_input = find_master_input(self.inputs, own_ref)
        let (new_output, new_output_index) = find_master_output_with_index(self.outputs, master_input.address)
        let new_datum = datum_from_output(new_output)

        expect new_datum.nonce == old_datum.nonce + 1
        expect new_datum.self_ref == make_output_ref(self.id, new_output_index)

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

        expect new_datum.stats == old_datum.stats
        expect new_datum.owner_address == old_datum.owner_address
        expect new_datum.is_paused == old_datum.is_paused
        expect new_datum.policy_id == old_datum.policy_id
        expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
        expect new_datum.forward_link == old_datum.forward_link
        expect new_datum.backward_link == old_datum.backward_link

        True
      }

      LinkForward {
        nonce,
        next_script_address,
        next_policy_id,
        link_reason,
        linked_at,
        instructions,
        signature,
      } -> {
        expect nonce == old_datum.nonce
        
        // Permanent Lockout Guard: Can only link forward ONCE
        expect old_datum.forward_link == None

        let signed_payload =
          bytearray.concat(
            bytearray.concat(
              bytearray.concat(
                bytearray.from_int_big_endian(nonce, 8), 
                next_policy_id
              ),
              next_script_address,
            ),
            link_reason,
          )
        expect verify_ed25519_signature(old_datum.authority_key, signed_payload, signature)

        let master_input = find_master_input(self.inputs, own_ref)
        let (new_output, new_output_index) = find_master_output_with_index(self.outputs, master_input.address)
        let new_datum = datum_from_output(new_output)

        expect new_datum.nonce == old_datum.nonce + 1
        expect new_datum.self_ref == make_output_ref(self.id, new_output_index)

        // Enforce clean state transition onto forward slot
        expect Some(link) = new_datum.forward_link
        expect link.next_script_address == next_script_address
        expect link.next_policy_id == next_policy_id
        expect link.link_reason == link_reason
        expect link.linked_at == linked_at
        expect link.instructions == instructions
        expect link.current_authority_key == old_datum.authority_key
        expect link.signature == signature
        expect link.nonce_at_link == nonce

        // Preserve Backward link track untouched
        expect new_datum.backward_link == old_datum.backward_link

        // Standard administration safety pass-throughs
        expect new_datum.stats == old_datum.stats
        expect new_datum.authority_key == old_datum.authority_key
        expect new_datum.operator_key == old_datum.operator_key
        expect new_datum.owner_key == old_datum.owner_key
        expect new_datum.owner_address == old_datum.owner_address
        expect new_datum.is_paused == old_datum.is_paused
        expect new_datum.policy_id == old_datum.policy_id
        expect new_datum.asset_name_prefix == old_datum.asset_name_prefix

        True
      }

      LinkBackward {
        nonce,
        prev_script_address,
        prev_policy_id,
        link_reason,
        linked_at,
        instructions,
        signature,
      } -> {
        expect nonce == old_datum.nonce
        
        // Permanent Lockout Guard: Can only link backward ONCE
        expect old_datum.backward_link == None

        let signed_payload =
          bytearray.concat(
            bytearray.concat(
              bytearray.concat(
                bytearray.from_int_big_endian(nonce, 8), 
                prev_policy_id
              ),
              prev_script_address,
            ),
            link_reason,
          )
        expect verify_ed25519_signature(old_datum.authority_key, signed_payload, signature)

        let master_input = find_master_input(self.inputs, own_ref)
        let (new_output, new_output_index) = find_master_output_with_index(self.outputs, master_input.address)
        let new_datum = datum_from_output(new_output)

        expect new_datum.nonce == old_datum.nonce + 1
        expect new_datum.self_ref == make_output_ref(self.id, new_output_index)

        // Enforce clean state transition onto backward slot
        expect Some(link) = new_datum.backward_link
        expect link.next_script_address == prev_script_address
        expect link.next_policy_id == prev_policy_id
        expect link.link_reason == link_reason
        expect link.linked_at == linked_at
        expect link.instructions == instructions
        expect link.current_authority_key == old_datum.authority_key
        expect link.signature == signature
        expect link.nonce_at_link == nonce

        // Preserve Forward link track untouched
        expect new_datum.forward_link == old_datum.forward_link

        // Standard administration safety pass-throughs
        expect new_datum.stats == old_datum.stats
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
        let minted_assets = assets.tokens(self.mint, policy_id)
        expect [Pair(asset_name, quantity)] = dict.to_pairs(minted_assets)
        expect quantity == 1

        expect Some(master_input) =
          list.find(self.inputs, fn(i) { i.output.address.payment_credential == Script(policy_id) })

        expect InlineDatum(datum_data) = master_input.output.datum
        expect master_datum: MasterDatum = datum_data

        let prefix = master_datum.asset_name_prefix
        let prefix_len = bytearray.length(prefix)
        expect bytearray.take(asset_name, prefix_len) == prefix

        let token_output_datum = find_token_output_with_datum(self.outputs, policy_id)
        
        let expected_asset_id = bytearray.concat(policy_id, asset_name)
        expect token_output_datum.cardano_asset_id == expected_asset_id

        True
      }

      BurnToken -> False
    }
  }
}