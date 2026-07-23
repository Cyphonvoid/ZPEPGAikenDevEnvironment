// =============================================================================
// CONTRACT NAME: ArchiveRegistry
// VERSION: 3.2 — Full Address Continuity For Document Tokens
// PURPOSE: A decentralized, immutable document metadata registry and native
//          token asset issuance contract built on Cardano's eUTXO model.
//
// ── SECURITY MODEL ───────────────────────────────────────────────────────────
// The fundamental invariant of this contract is:
//   "Citizen UTXOs can NEVER leave this script's address"
//
// Citizen UTXOs are defined as any UTXO carrying a token under own_policy_id:
//   - Master UTXO      → carries beacon token (ZPE_BEACON)
//   - Document UTXOs   → carry document tokens (ZPE_DOC-...)
//   - Reference UTXO   → carries reference token (ZPE_REF)
//
// This invariant is enforced by TWO independent mechanisms working together:
//
// MECHANISM 1 — BEACON TOKEN (Canonical Identity)
//   The beacon token is a one-shot mint, exactly one exists ever. It moves
//   forward with every state-changing transaction. It is the unforgeable
//   canonical identifier of the master UTXO among all UTXOs at this address.
//   You cannot forge it. You cannot copy it. To have it you must have received
//   it through this validator with valid keys.
//
// MECHANISM 2 — TRIPLE VERIFICATION (Jurisdiction Enforcement)
//   Every state-changing branch performs full verification before any logic:
//     a) Runtime derived own_policy_id (from ledger-injected own_ref,
//        extracted from the payment credential of the UTXO being spent —
//        this is not user supplied, it is the ledger's own execution context)
//     b) Genesis-stored script_hash in MasterDatum (written once at genesis,
//        frozen permanently — every branch asserts new == old)
//     c) Full address continuity — new master output address must exactly
//        equal master_input.address (the ledger-guaranteed address of the
//        UTXO being consumed). Pins BOTH payment AND stake credential.
//        Genesis sets the address via MintBeacon. Every transaction enforces
//        new == old. The chain is unbreakable — address can never drift.
//
// PERMISSION KEY MODEL
//   Keys (authority, operator, owner) are administrative controls only.
//   They manage WHO can perform operations, not WHETHER the contract's
//   structural invariants hold. A compromised key means loss of administrative
//   control. It NEVER means a citizen UTXO can leave the script. The contract
//   is designed to be structurally unbreakable regardless of key state.
//
// ── DEPLOYMENT SEQUENCE (TWO STAGES) ────────────────────────────────────────
// Stage 1 — Genesis:
//   - Run `aiken build` locally → script_hash is known before any deployment
//   - Spend genesis_utxo_ref (one-shot authorization)
//   - Mint beacon token (ZPE_BEACON) via MintBeacon redeemer
//   - Create initial MasterDatum with script_hash filled in from local build
//   - Send master UTXO to Script(script_hash) address
//
// Stage 2 — Reference UTXO:
//   - Deploy compiled script bytecode as reference UTXO
//   - Simultaneously mint reference token (ZPE_REF) via MintReference redeemer
//   - Spend reference_utxo_ref (one-shot authorization)
//   - Reference UTXO now carries ZPE_REF token → it is a citizen UTXO
//   - Protected from sweep automatically (carries policy token)
//   - Visible and identifiable on-chain like beacon and document tokens
//
// ── NON-CITIZEN UTXO SWEEP ───────────────────────────────────────────────────
// Plain ADA accidentally sent to this address (no datum, no tokens) can be
// swept via SweepFunds redeemer. Citizen UTXOs are structurally blocked:
//   - Master UTXO    → has beacon token (policy token check blocks it)
//   - Document UTXOs → have policy tokens (same check blocks them)
//   - Reference UTXO → has ZPE_REF token (same check blocks it)
// The sweep path has no code that touches or produces a master output.
// It is structurally incapable of spending citizen UTXOs.
//
// =============================================================================

use cardano/assets
use aiken/collection/dict
use aiken/primitive/bytearray
use aiken/crypto.{VerificationKey, Signature, verify_ed25519_signature}
use cardano/address.{Address, Script}
use cardano/transaction.{
  OutputReference, Transaction, Input, Output, InlineDatum,
}
use aiken/collection/list

// ── REGISTRY STATS ────────────────────────────────────────────────────────────
pub type RegistryStats {
  total_token_count: Int,
  total_unique_documents: Int,
  last_minted_at: Int,
  last_cross_chain_global_id: ByteArray,
  last_cardano_asset_id: ByteArray,
}

// ── MASTER REGISTRY DATUM ────────────────────────────────────────────────────
pub type MasterDatum {
  // Administrative keys — control WHO can perform operations
  // Compromising these never compromises structural invariants
  authority_key: VerificationKey,
  operator_key: VerificationKey,
  owner_key: VerificationKey,
  owner_address: Address,

  // Operational state
  nonce: Int,
  is_paused: Bool,

  // Token naming
  policy_id: ByteArray,
  asset_name_prefix: ByteArray,

  // Deployment chain links (one-time write, then frozen)
  forward_link: Option<DeploymentChainLink>,
  backward_link: Option<DeploymentChainLink>,

  // Registry metrics
  stats: RegistryStats,

  // Human readable naming fields (frozen after genesis)
  asset_name_scheme_for_humans: ByteArray,
  asset_name_example_for_humans: ByteArray,
  asset_name_description_for_humans: ByteArray,

  // ── SECURITY CRITICAL FIELD ───────────────────────────────────────────────
  // script_hash is the hash of this contract's compiled bytecode.
  // It is known from `aiken build` before any deployment occurs.
  // It is written ONCE at genesis and NEVER changes thereafter.
  // Every branch asserts: new_datum.script_hash == old_datum.script_hash
  // Used for dual verification: runtime derived own_policy_id must equal
  // this stored value before any state transition is permitted.
  // Also used to enforce: new master output payment_credential == Script(script_hash)
  script_hash: ByteArray,
}

// ── DEPLOYMENT CHAIN LINK ─────────────────────────────────────────────────────
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

// ── TOKEN DATUM (per minted document) ────────────────────────────────────────
pub type TokenDatum {
  cardano_asset_id: ByteArray,
  cross_chain_global_id: ByteArray,
  registry_address: ByteArray,
  policy_id: ByteArray,
  source_registry_master_utxo_reference: OutputReference,
  sha256_hash: ByteArray,
  upload_date: ByteArray,
  version: Int,
  token_data: ByteArray,
}

// ── SPEND REDEEMER ───────────────────────────────────────────────────────────
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
  SweepFunds {
    amount: Int,
    to_address: Address,
    signature: Signature,
  }
}

pub type KeyType {
  AuthorityKey
  OperatorKey
  OwnerKey
}

// ── MINT REDEEMER ─────────────────────────────────────────────────────────────
pub type CreateTokenAction {
  MintBeacon     // Stage 1 genesis — one-shot, consumes genesis_utxo_ref
  MintReference  // Stage 2 reference UTXO — one-shot, consumes reference_utxo_ref
  MintToken      // Document token minting — ongoing, authorized by spend validator
  BurnToken      // Always fails — tokens are permanent
}

// ── HELPERS ───────────────────────────────────────────────────────────────────

// Find the input currently being spent via ledger-injected own_ref
// own_ref is NOT user supplied — it is injected by the Cardano ledger
fn find_master_input(inputs: List<Input>, own_ref: OutputReference) -> Output {
  expect Some(input) =
    list.find(inputs, fn(i) { i.output_reference == own_ref })
  input.output
}

// Extract script hash from a script address payment credential
// Fails hard if not a script address — this should never happen for master UTXO
fn own_script_hash(addr: Address) -> ByteArray {
  when addr.payment_credential is {
    Script(h) -> h
    _ -> fail @"Master UTXO is not locked at a script address"
  }
}

// Find the canonical master output by beacon token presence
// Beacon is unforgeable — only one exists ever, minted once at genesis
fn find_master_output_by_beacon(
  outputs: List<Output>,
  beacon_policy_id: ByteArray,
  beacon_asset_name: ByteArray,
) -> Output {
  when outputs is {
    [] -> fail @"Master output holding beacon token not found"
    [head, ..tail] ->
      if assets.quantity_of(head.value, beacon_policy_id, beacon_asset_name) == 1 {
        head
      } else {
        find_master_output_by_beacon(tail, beacon_policy_id, beacon_asset_name)
      }
  }
}

// Find document token output with matching datum
// Uses full address equality against the triple-verified master output address.
// master_address is new_output.address from verify_master_transition —
// the most verified value in the transaction, anchored to genesis via the
// unbreakable continuity chain. Document tokens must land at exactly this
// address — same payment credential AND same stake credential as master UTXO.
fn find_token_output_with_datum(
  outputs: List<Output>,
  policy_id: ByteArray,
  asset_name: ByteArray,
  beacon_policy_id: ByteArray,
  beacon_asset_name: ByteArray,
  master_address: Address,
) -> TokenDatum {
  when outputs is {
    [] -> fail @"Token output with matching TokenDatum not found at script address"
    [head, ..tail] -> {
      // Skip the master output (it carries the beacon)
      let holds_beacon =
        assets.quantity_of(head.value, beacon_policy_id, beacon_asset_name) == 1
      if holds_beacon {
        find_token_output_with_datum(tail, policy_id, asset_name, beacon_policy_id, beacon_asset_name, master_address)
      } else {
        when head.datum is {
          InlineDatum(datum_data) -> {
            expect token_datum: TokenDatum = datum_data
            let holds_asset = assets.quantity_of(head.value, policy_id, asset_name) == 1
            // Full address equality — anchored to triple-verified master output address.
            // Document token must land at exactly the same address as the master UTXO.
            // This pins both payment credential AND stake credential consistently.
            let at_script = head.address == master_address
            if token_datum.policy_id == policy_id && holds_asset && at_script {
              token_datum
            } else {
              find_token_output_with_datum(tail, policy_id, asset_name, beacon_policy_id, beacon_asset_name, master_address)
            }
          }
          _ -> find_token_output_with_datum(tail, policy_id, asset_name, beacon_policy_id, beacon_asset_name, master_address)
        }
      }
    }
  }
}

fn datum_from_output(output: Output) -> MasterDatum {
  expect InlineDatum(datum_data) = output.datum
  expect master_datum: MasterDatum = datum_data
  master_datum
}

fn require_beacon_carried_forward(
  output: Output,
  beacon_policy_id: ByteArray,
  beacon_asset_name: ByteArray,
) {
  expect assets.quantity_of(output.value, beacon_policy_id, beacon_asset_name) == 1
}

// ── CORE SECURITY HELPER ─────────────────────────────────────────────────────
// This function MUST be called at the start of every state-changing branch.
// It performs the complete dual verification and returns verified values.
//
// Returns: (own_policy_id, new_output, new_datum)
//
// Security guarantees provided:
//   1. own_policy_id is derived from ledger execution context (not user supplied)
//   2. own_policy_id matches genesis-stored script_hash (dual verification)
//   3. new_output is the canonical master output (identified by beacon)
//   4. new_output address exactly matches master_input address (full address continuity)
//      — master_input.address is ledger-guaranteed (the UTXO being consumed),
//        pinned to Script(policy_id) since genesis by MintBeacon.
//        Every transaction enforces new == old, forming an unbreakable chain.
//        Both payment AND stake credential are frozen — nothing can silently drift.
//   5. beacon is carried forward (continuity)
//   6. new_datum carries same script_hash (frozen field continuity)
fn verify_master_transition(
  inputs: List<Input>,
  outputs: List<Output>,
  own_ref: OutputReference,
  old_datum: MasterDatum,
  beacon_asset_name: ByteArray,
) -> (ByteArray, Output, MasterDatum) {
  // STEP 1: Derive own_policy_id from ledger execution context
  // own_ref is ledger-injected — not user supplied
  // master_input is the UTXO the ledger is currently consuming
  // own_policy_id is extracted from its payment credential
  // This IS this script's hash, by definition of how Cardano executes validators
  let master_input = find_master_input(inputs, own_ref)
  let own_policy_id = own_script_hash(master_input.address)

  // STEP 2: Dual verification
  // Runtime derived value must match genesis-stored frozen value
  // If these disagree something is fundamentally compromised
  expect own_policy_id == old_datum.script_hash

  // STEP 3: Find canonical master output by beacon
  // Beacon is unforgeable — this correctly identifies the new master UTXO
  let new_output =
    find_master_output_by_beacon(outputs, own_policy_id, beacon_asset_name)

  // STEP 4: Full address continuity
  // new_output.address must exactly equal master_input.address —
  // the ledger-guaranteed address of the UTXO being consumed right now.
  // This pins BOTH payment credential AND stake credential.
  // The chain: genesis sets the address via MintBeacon → every subsequent
  // transaction enforces new == old → address can never drift in any field.
  expect new_output.address == master_input.address

  // STEP 5: Beacon continuity
  // Beacon must be present in new output (carried forward)
  require_beacon_carried_forward(new_output, own_policy_id, beacon_asset_name)

  // STEP 6: Read new datum
  let new_datum = datum_from_output(new_output)

  // STEP 7: script_hash frozen
  // The frozen genesis value must never change
  expect new_datum.script_hash == old_datum.script_hash

  (own_policy_id, new_output, new_datum)
}

// ── VALIDATOR ─────────────────────────────────────────────────────────────────
validator archive_registry(
  genesis_utxo_ref: OutputReference,    // Stage 1: one-shot genesis authorization
  reference_utxo_ref: OutputReference,  // Stage 2: one-shot reference UTXO authorization
  beacon_asset_name: ByteArray,         // Compile-time fixed beacon asset name
  reference_asset_name: ByteArray,      // Compile-time fixed reference asset name
) {

  spend(
    datum: Option<MasterDatum>,
    redeemer: RegistryAction,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    when datum is {

      // ── NON-CITIZEN SWEEP PATH ─────────────────────────────────────────────
      // UTXOs at this script address with no datum are non-citizens
      // (plain ADA accidentally sent by anyone).
      // This path is STRUCTURALLY INCAPABLE of spending citizen UTXOs:
      //   - Has no code to find or produce a master output
      //   - Guards against any UTXO carrying a policy token (blocks all citizens)
      None -> {
        // Only SweepFunds is valid for datum-less UTXOs
        expect SweepFunds { amount, to_address, signature } = redeemer

        // Find the UTXO being spent (ledger injected own_ref)
        let own_input = find_master_input(self.inputs, own_ref)
        let own_policy_id = own_script_hash(own_input.address)

        // ── CITIZEN UTXO GUARD ─────────────────────────────────────────────
        // Any UTXO carrying ANY token under own_policy_id is a citizen:
        //   - Master UTXO    → has beacon token (policy token)
        //   - Document UTXOs → have document tokens (policy tokens)
        //   - Reference UTXO → has ZPE_REF token (policy token)
        // All citizens are blocked here. Only pure ADA UTXOs pass.
        // This check is unforgeable — only this script can mint policy tokens.
        expect dict.size(assets.tokens(own_input.value, own_policy_id)) == 0

        // ── READ MASTER UTXO AS REFERENCE INPUT FOR KEY VALIDATION ─────────
        // Master UTXO is NOT spent here — it is read as a reference input only
        // This is the correct pattern — sweep never touches the master UTXO
        expect Some(master_ref_input) =
          list.find(
            self.reference_inputs,
            fn(i) {
              assets.quantity_of(i.output.value, own_policy_id, beacon_asset_name) == 1
            },
          )
        expect InlineDatum(datum_data) = master_ref_input.output.datum
        expect master_datum: MasterDatum = datum_data

        // ── SIGNED PAYLOAD ────────────────────────────────────────────────
        // Includes:
        //   - nonce: prevents replay across different nonce states
        //   - "SWEEP_FUNDS": domain separator
        //   - amount: binds signature to specific amount
        //   - own_ref tx hash + index: binds signature to THIS specific UTXO
        //     (prevents replay against future UTXOs at this address)
        //   - to_address payment credential bytes: binds destination
        //     (prevents destination tampering after signing)
        let own_ref_bytes =
          bytearray.concat(
            own_ref.transaction_id,
            bytearray.from_int_big_endian(own_ref.output_index, 4),
          )

        // Serialize to_address for signing
        // We sign the payment credential bytes to bind the destination
        let to_address_bytes =
          when to_address.payment_credential is {
            Script(h) -> bytearray.concat("S", h)
            _ -> bytearray.concat("V",
              when to_address.payment_credential is {
                address.VerificationKey(h) -> h
                _ -> fail @"Unexpected credential type"
              }
            )
          }

        let signed_payload =
          bytearray.concat(
            bytearray.concat(
              bytearray.concat(
                bytearray.concat(
                  bytearray.from_int_big_endian(master_datum.nonce, 8),
                  "SWEEP_FUNDS",
                ),
                bytearray.from_int_big_endian(amount, 8),
              ),
              own_ref_bytes,
            ),
            to_address_bytes,
          )

        // Any of the three keys may authorize a sweep
        expect
          verify_ed25519_signature(master_datum.authority_key, signed_payload, signature) ||
          verify_ed25519_signature(master_datum.operator_key, signed_payload, signature) ||
          verify_ed25519_signature(master_datum.owner_key, signed_payload, signature)

        // Validate withdrawal output goes to the signed destination address
        expect
          list.any(
            self.outputs,
            fn(o) {
              o.address == to_address &&
              assets.lovelace_of(o.value) == amount
            },
          )

        True
      }

      // ── CITIZEN SPEND PATH ────────────────────────────────────────────────
      // All state-changing operations on the master UTXO
      Some(old_datum) -> {
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
            signature,
          } -> {
            // ── DUAL VERIFICATION + JURISDICTION ENFORCEMENT ───────────────
            let (own_policy_id, new_output, new_datum) =
              verify_master_transition(
                self.inputs, self.outputs, own_ref, old_datum, beacon_asset_name,
              )

            // ── AUTHORIZATION ──────────────────────────────────────────────
            trace @"TRACE:MD:nonce_mismatch"
            expect nonce == old_datum.nonce
            trace @"TRACE:MD:contract_paused"
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

            trace @"TRACE:MD:sig_invalid"
            expect verify_ed25519_signature(
              old_datum.operator_key,
              signed_payload,
              signature,
            )

            // ── MINTED ASSET VALIDATION ────────────────────────────────────
            let minted_assets = assets.tokens(self.mint, old_datum.policy_id)
            trace @"TRACE:MD:minted_assets_not_singleton"
            expect [Pair(asset_name, mint_quantity)] = dict.to_pairs(minted_assets)
            trace @"TRACE:MD:mint_quantity_not_1"
            expect mint_quantity == 1

            // ── ASSET NAME FORMAT VALIDATION ───────────────────────────────
            // Expected: "ZPE_DOC-" + 20 uuid chars + "_v" + 1-2 version digits
            let prefix = "ZPE_DOC-"
            let separator = "_v"
            let prefix_len = 8
            let uuid_len = 20
            let separator_len = 2
            let asset_name_len = bytearray.length(asset_name)

            trace @"TRACE:MD:asset_name_prefix_mismatch"
            expect bytearray.take(asset_name, prefix_len) == prefix

            let uuid_portion = bytearray.slice(asset_name, prefix_len, prefix_len + uuid_len - 1)
            trace @"TRACE:MD:asset_name_uuid_wrong_length"
            expect bytearray.length(uuid_portion) == uuid_len

            let sep_start = prefix_len + uuid_len
            trace @"TRACE:MD:asset_name_separator_mismatch"
            expect bytearray.slice(asset_name, sep_start, sep_start + separator_len - 1) == separator

            let version_start = sep_start + separator_len
            let version_len = asset_name_len - version_start
            trace @"TRACE:MD:asset_name_version_wrong_length"
            expect version_len >= 1 && version_len <= 2

            trace @"TRACE:MD:asset_name_uuid_mismatch"
            expect uuid_portion == bytearray.take(cross_chain_global_id, uuid_len)

            // ── TOKEN OUTPUT VALIDATION ────────────────────────────────────
            // Pass new_output.address — the triple-verified master address.
            // Document tokens must land at exactly this address (full equality).
            let token_output_datum =
              find_token_output_with_datum(
                self.outputs,
                old_datum.policy_id,
                asset_name,
                own_policy_id,
                beacon_asset_name,
                new_output.address,
              )

            trace @"TRACE:MD:token_global_id_mismatch"
            expect token_output_datum.cross_chain_global_id == cross_chain_global_id
            trace @"TRACE:MD:token_registry_address_not_empty"
            expect token_output_datum.registry_address == #""
            trace @"TRACE:MD:token_policy_id_mismatch"
            expect token_output_datum.policy_id == old_datum.policy_id
            trace @"TRACE:MD:token_utxo_ref_mismatch"
            expect token_output_datum.source_registry_master_utxo_reference == own_ref
            trace @"TRACE:MD:token_sha256_mismatch"
            expect token_output_datum.sha256_hash == sha256_hash
            trace @"TRACE:MD:token_upload_date_mismatch"
            expect token_output_datum.upload_date == upload_date
            trace @"TRACE:MD:token_version_mismatch"
            expect token_output_datum.version == version
            trace @"TRACE:MD:token_data_mismatch"
            expect token_output_datum.token_data == token_data

            // ── MASTER DATUM UPDATE VALIDATION ─────────────────────────────
            trace @"TRACE:MD:new_nonce_wrong"
            expect new_datum.nonce == old_datum.nonce + 1
            trace @"TRACE:MD:token_count_wrong"
            expect new_datum.stats.total_token_count == old_datum.stats.total_token_count + 1

            let expected_unique_inc = if is_unique_document { 1 } else { 0 }
            trace @"TRACE:MD:unique_docs_wrong"
            expect new_datum.stats.total_unique_documents == old_datum.stats.total_unique_documents + expected_unique_inc
            trace @"TRACE:MD:last_minted_at_wrong"
            expect new_datum.stats.last_minted_at == valid_lower_bound
            trace @"TRACE:MD:last_global_id_wrong"
            expect new_datum.stats.last_cross_chain_global_id == cross_chain_global_id
            trace @"TRACE:MD:last_asset_id_wrong"
            expect new_datum.stats.last_cardano_asset_id == token_output_datum.cardano_asset_id

            // ── FROZEN FIELD CONTINUITY ────────────────────────────────────
            trace @"TRACE:MD:authority_key_changed"
            expect new_datum.authority_key == old_datum.authority_key
            trace @"TRACE:MD:operator_key_changed"
            expect new_datum.operator_key == old_datum.operator_key
            trace @"TRACE:MD:owner_key_changed"
            expect new_datum.owner_key == old_datum.owner_key
            trace @"TRACE:MD:owner_address_changed"
            expect new_datum.owner_address == old_datum.owner_address
            trace @"TRACE:MD:is_paused_changed"
            expect new_datum.is_paused == old_datum.is_paused
            trace @"TRACE:MD:policy_id_changed"
            expect new_datum.policy_id == old_datum.policy_id
            trace @"TRACE:MD:asset_name_prefix_changed"
            expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
            trace @"TRACE:MD:forward_link_changed"
            expect new_datum.forward_link == old_datum.forward_link
            trace @"TRACE:MD:backward_link_changed"
            expect new_datum.backward_link == old_datum.backward_link
            expect new_datum.asset_name_scheme_for_humans == old_datum.asset_name_scheme_for_humans
            expect new_datum.asset_name_example_for_humans == old_datum.asset_name_example_for_humans
            expect new_datum.asset_name_description_for_humans == old_datum.asset_name_description_for_humans
            // script_hash frozen — enforced inside verify_master_transition

            True
          }

          Pause { nonce, signature } -> {
            // ── DUAL VERIFICATION + JURISDICTION ENFORCEMENT ───────────────
            let (_, _new_output, new_datum) =
              verify_master_transition(
                self.inputs, self.outputs, own_ref, old_datum, beacon_asset_name,
              )

            expect nonce == old_datum.nonce
            expect old_datum.is_paused == False
            let signed_payload =
              bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "PAUSE")
            expect verify_ed25519_signature(old_datum.authority_key, signed_payload, signature)

            expect new_datum.nonce == old_datum.nonce + 1
            expect new_datum.is_paused == True

            expect new_datum.stats == old_datum.stats
            expect new_datum.authority_key == old_datum.authority_key
            expect new_datum.operator_key == old_datum.operator_key
            expect new_datum.owner_key == old_datum.owner_key
            expect new_datum.owner_address == old_datum.owner_address
            expect new_datum.policy_id == old_datum.policy_id
            expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
            expect new_datum.forward_link == old_datum.forward_link
            expect new_datum.backward_link == old_datum.backward_link
            expect new_datum.asset_name_scheme_for_humans == old_datum.asset_name_scheme_for_humans
            expect new_datum.asset_name_example_for_humans == old_datum.asset_name_example_for_humans
            expect new_datum.asset_name_description_for_humans == old_datum.asset_name_description_for_humans

            True
          }

          Resume { nonce, signature } -> {
            // ── DUAL VERIFICATION + JURISDICTION ENFORCEMENT ───────────────
            let (_, _new_output, new_datum) =
              verify_master_transition(
                self.inputs, self.outputs, own_ref, old_datum, beacon_asset_name,
              )

            expect nonce == old_datum.nonce
            expect old_datum.is_paused == True
            let signed_payload =
              bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "RESUME")
            expect verify_ed25519_signature(old_datum.authority_key, signed_payload, signature)

            expect new_datum.nonce == old_datum.nonce + 1
            expect new_datum.is_paused == False

            expect new_datum.stats == old_datum.stats
            expect new_datum.authority_key == old_datum.authority_key
            expect new_datum.operator_key == old_datum.operator_key
            expect new_datum.owner_key == old_datum.owner_key
            expect new_datum.owner_address == old_datum.owner_address
            expect new_datum.policy_id == old_datum.policy_id
            expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
            expect new_datum.forward_link == old_datum.forward_link
            expect new_datum.backward_link == old_datum.backward_link
            expect new_datum.asset_name_scheme_for_humans == old_datum.asset_name_scheme_for_humans
            expect new_datum.asset_name_example_for_humans == old_datum.asset_name_example_for_humans
            expect new_datum.asset_name_description_for_humans == old_datum.asset_name_description_for_humans

            True
          }

          RotateKey { nonce, key_type, new_key, signature } -> {
            // ── DUAL VERIFICATION + JURISDICTION ENFORCEMENT ───────────────
            let (_, _new_output, new_datum) =
              verify_master_transition(
                self.inputs, self.outputs, own_ref, old_datum, beacon_asset_name,
              )

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

            expect new_datum.nonce == old_datum.nonce + 1

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
            expect new_datum.asset_name_scheme_for_humans == old_datum.asset_name_scheme_for_humans
            expect new_datum.asset_name_example_for_humans == old_datum.asset_name_example_for_humans
            expect new_datum.asset_name_description_for_humans == old_datum.asset_name_description_for_humans

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
            // ── DUAL VERIFICATION + JURISDICTION ENFORCEMENT ───────────────
            let (_, _new_output, new_datum) =
              verify_master_transition(
                self.inputs, self.outputs, own_ref, old_datum, beacon_asset_name,
              )

            expect nonce == old_datum.nonce
            expect old_datum.forward_link == None

            let signed_payload =
              bytearray.concat(
                bytearray.concat(
                  bytearray.concat(
                    bytearray.from_int_big_endian(nonce, 8),
                    next_policy_id,
                  ),
                  next_script_address,
                ),
                link_reason,
              )
            expect verify_ed25519_signature(old_datum.authority_key, signed_payload, signature)

            expect new_datum.nonce == old_datum.nonce + 1

            expect Some(link) = new_datum.forward_link
            expect link.next_script_address == next_script_address
            expect link.next_policy_id == next_policy_id
            expect link.link_reason == link_reason
            expect link.linked_at == linked_at
            expect link.instructions == instructions
            expect link.current_authority_key == old_datum.authority_key
            expect link.signature == signature
            expect link.nonce_at_link == nonce

            expect new_datum.backward_link == old_datum.backward_link
            expect new_datum.stats == old_datum.stats
            expect new_datum.authority_key == old_datum.authority_key
            expect new_datum.operator_key == old_datum.operator_key
            expect new_datum.owner_key == old_datum.owner_key
            expect new_datum.owner_address == old_datum.owner_address
            expect new_datum.is_paused == old_datum.is_paused
            expect new_datum.policy_id == old_datum.policy_id
            expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
            expect new_datum.asset_name_scheme_for_humans == old_datum.asset_name_scheme_for_humans
            expect new_datum.asset_name_example_for_humans == old_datum.asset_name_example_for_humans
            expect new_datum.asset_name_description_for_humans == old_datum.asset_name_description_for_humans

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
            // ── DUAL VERIFICATION + JURISDICTION ENFORCEMENT ───────────────
            let (_, _new_output, new_datum) =
              verify_master_transition(
                self.inputs, self.outputs, own_ref, old_datum, beacon_asset_name,
              )

            expect nonce == old_datum.nonce
            expect old_datum.backward_link == None

            let signed_payload =
              bytearray.concat(
                bytearray.concat(
                  bytearray.concat(
                    bytearray.from_int_big_endian(nonce, 8),
                    prev_policy_id,
                  ),
                  prev_script_address,
                ),
                link_reason,
              )
            expect verify_ed25519_signature(old_datum.authority_key, signed_payload, signature)

            expect new_datum.nonce == old_datum.nonce + 1

            expect Some(link) = new_datum.backward_link
            expect link.next_script_address == prev_script_address
            expect link.next_policy_id == prev_policy_id
            expect link.link_reason == link_reason
            expect link.linked_at == linked_at
            expect link.instructions == instructions
            expect link.current_authority_key == old_datum.authority_key
            expect link.signature == signature
            expect link.nonce_at_link == nonce

            expect new_datum.forward_link == old_datum.forward_link
            expect new_datum.stats == old_datum.stats
            expect new_datum.authority_key == old_datum.authority_key
            expect new_datum.operator_key == old_datum.operator_key
            expect new_datum.owner_key == old_datum.owner_key
            expect new_datum.owner_address == old_datum.owner_address
            expect new_datum.is_paused == old_datum.is_paused
            expect new_datum.policy_id == old_datum.policy_id
            expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
            expect new_datum.asset_name_scheme_for_humans == old_datum.asset_name_scheme_for_humans
            expect new_datum.asset_name_example_for_humans == old_datum.asset_name_example_for_humans
            expect new_datum.asset_name_description_for_humans == old_datum.asset_name_description_for_humans

            True
          }

          // SweepFunds with Some(datum) is structurally rejected
          // Citizen UTXOs (those with datums) can never be swept
          SweepFunds { .. } -> False
        }
      }
    }
  }

  mint(token_action: CreateTokenAction, policy_id: ByteArray, self: Transaction) {
    when token_action is {

      // ── STAGE 1: GENESIS ───────────────────────────────────────────────────
      // One-shot beacon mint. Can only ever fire once because genesis_utxo_ref
      // is consumed — it can never exist again on the ledger.
      MintBeacon -> {
        // Verify genesis UTXO is being consumed (one-shot authorization)
        expect list.any(self.inputs, fn(i) { i.output_reference == genesis_utxo_ref })

        // Verify exactly one beacon token is minted, nothing else
        let minted_assets = assets.tokens(self.mint, policy_id)
        expect [Pair(asset_name, quantity)] = dict.to_pairs(minted_assets)
        expect asset_name == beacon_asset_name
        expect quantity == 1

        // Verify beacon lands at this script's address
        // payment_credential == Script(policy_id) means only this script can spend it
        // policy_id IS this script's hash (unified single script architecture)
        expect Some(genesis_output) =
          list.find(
            self.outputs,
            fn(o) {
              assets.quantity_of(o.value, policy_id, beacon_asset_name) == 1 &&
              o.address.payment_credential == Script(policy_id)
            },
          )

        // Verify script_hash in genesis MasterDatum equals actual policy_id
        // This prevents permanent contract death from a misconfigured genesis datum.
        // If script_hash is wrong, every future verify_master_transition call
        // would fail permanently with no on-chain recovery path.
        expect InlineDatum(genesis_datum_data) = genesis_output.datum
        expect genesis_datum: MasterDatum = genesis_datum_data
        expect genesis_datum.script_hash == policy_id

        True
      }

      // ── STAGE 2: REFERENCE UTXO ────────────────────────────────────────────
      // One-shot reference token mint. Gives the reference script UTXO a
      // policy token, making it a citizen UTXO — permanently protected from
      // sweep and identifiable on-chain like the beacon and document tokens.
      MintReference -> {
        // Verify reference UTXO is being consumed (one-shot authorization)
        expect list.any(self.inputs, fn(i) { i.output_reference == reference_utxo_ref })

        // Verify exactly one reference token is minted, nothing else
        let minted_assets = assets.tokens(self.mint, policy_id)
        expect [Pair(asset_name, quantity)] = dict.to_pairs(minted_assets)
        expect asset_name == reference_asset_name
        expect quantity == 1

        // Verify reference token lands at this script's address
        expect Some(_) =
          list.find(
            self.outputs,
            fn(o) {
              assets.quantity_of(o.value, policy_id, reference_asset_name) == 1 &&
              o.address.payment_credential == Script(policy_id)
            },
          )

        True
      }

      // ── ONGOING: DOCUMENT TOKEN MINTING ───────────────────────────────────
      // Authorized by the spend validator (MintDocument branch).
      // Finds master input by beacon — unforgeable canonical identity.
      MintToken -> {
        let minted_assets = assets.tokens(self.mint, policy_id)
        trace @"TRACE:MT:minted_assets_not_singleton"
        expect [Pair(asset_name, quantity)] = dict.to_pairs(minted_assets)
        trace @"TRACE:MT:quantity_not_1"
        expect quantity == 1

        // Find master input by beacon — not by script credential
        // Beacon is unforgeable, this correctly identifies the canonical master UTXO
        trace @"TRACE:MT:master_input_not_found"
        expect Some(master_input) =
          list.find(
            self.inputs,
            fn(i) {
              assets.quantity_of(i.output.value, policy_id, beacon_asset_name) == 1
            },
          )

        trace @"TRACE:MT:master_input_no_inline_datum"
        expect InlineDatum(datum_data) = master_input.output.datum
        trace @"TRACE:MT:master_datum_deserialize_failed"
        expect master_datum: MasterDatum = datum_data

        // Beacon presence already confirmed above by the find condition
        // This is now redundant but kept for explicitness
        trace @"TRACE:MT:beacon_not_in_master_input"
        expect assets.quantity_of(
          master_input.output.value,
          policy_id,
          beacon_asset_name,
        ) == 1

        // Verify asset name prefix
        let prefix = "ZPE_DOC-"
        let prefix_len = 8
        trace @"TRACE:MT:asset_name_prefix_mismatch"
        expect bytearray.take(asset_name, prefix_len) == prefix

        // Find token output — anchored to master_input.output.address.
        // master_input was found by beacon (unforgeable), so its address
        // is the canonical verified script address. Document token must
        // land at exactly this address (full equality, not just payment cred).
        let token_output_datum =
          find_token_output_with_datum(
            self.outputs,
            policy_id,
            asset_name,
            policy_id,
            beacon_asset_name,
            master_input.output.address,
          )

        let expected_asset_id = bytearray.concat(policy_id, asset_name)
        trace @"TRACE:MT:cardano_asset_id_mismatch"
        expect token_output_datum.cardano_asset_id == expected_asset_id

        // Verify master_datum is used (suppress unused warning)
        expect master_datum.policy_id == policy_id

        True
      }
      
      // Burning is permanently disabled — document tokens are forever
      BurnToken -> False
    }
  }
}
