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
// ── CANONICAL MASTER UTXO DISCOVERY (BEACON TOKEN) ─────────────────────────
// Cardano addresses — script or otherwise — accept payments unconditionally
// from anyone. This means a decoy UTXO carrying a hand-crafted, structurally
// plausible MasterDatum can be sent to this script address at any time, by
// anyone, without ever invoking this contract's spend or mint logic (plain
// payments never run either). No datum-field check can distinguish a decoy
// from the real master UTXO, because datum fields are just data and can
// always be copied verbatim.
//
// This contract closes that gap with a beacon token: a single native asset,
// minted exactly once at genesis, that must be carried forward into every
// successor master UTXO. "The canonical master UTXO" is defined as
// "whichever UTXO holds this exact token" — a ledger-enforced, non-copyable
// fact, since eUTXO guarantees a given native asset unit can only ever sit
// in one place at a time. Decoys cannot acquire the beacon: they cannot
// mint a copy (this script's MintBeacon redeemer can only ever fire once,
// ever — see below), and they cannot obtain the existing unit without
// spending the real master UTXO, which requires the real signing keys.
//
// ── SINGLE-SCRIPT ARCHITECTURE (formerly two contracts) ────────────────────
// Earlier revisions of this system split beacon minting into its own
// separate script (beacon_contract.ak / beacon_policy.ak), compiled first
// against a chosen genesis UTXO, with its resulting policy ID then baked
// into a SEPARATE compilation of this registry script. That worked, but
// required careful two-stage deployment sequencing (beacon must compile and
// its policy ID become known BEFORE registry compilation can even begin)
// and meant tracking two coordinated script artifacts, two addresses, two
// policy IDs per deployment.
//
// This version collapses both into ONE script. archive_registry is itself
// parameterized at compile time by a genesis OutputReference and a fixed
// beacon_asset_name (see the `validator archive_registry(...)` declaration
// below) — exactly the same one-shot-minting pattern beacon_contract.ak
// used on its own, just folded directly into this script's own `mint`
// entrypoint as the MintBeacon redeemer variant. Since it's all one script,
// the beacon's policy ID and the registry's own policy ID are now the SAME
// value — there is nothing left to coordinate or hand off between two
// artifacts. MasterDatum no longer needs to carry beacon_policy_id /
// beacon_asset_name fields at all, since "is this the canonical UTXO" is
// now answered by checking against the script's OWN identity (derived from
// whatever address the spent master UTXO is locked at, which can only ever
// be this script's own address) and the compile-time-fixed asset name,
// rather than trusting a field read out of a datum.
//
// Genesis is now a single atomic step: spend the genesis UTXO (a normal,
// wallet-key-locked UTXO — its owner's signature on that input IS the
// authorization, no separate authority-key signature is needed for the
// one-shot beacon mint itself), mint the beacon under this script's own
// policy via the MintBeacon redeemer, and send the resulting output
// straight to this script's own address carrying the initial MasterDatum.
// No separate "registry bootstrap" stage exists anymore - the spend
// validator is never even invoked during genesis, since nothing is being
// spent FROM the script yet at that point.
//
// ── CARDANO SECURITY & ACCESS CONTROL HIERARCHY
// The contract enforces a strict, multi-tiered cryptographic signature
// framework using public key hashes stored inside the active registry state:
//   - Authority Key: The root system administrator. Exclusively authorized
//     to pause/resume operations, rotate keys, and establish deployment
//     linkages.
//   - Operator Key: A worker identity optimized for automated backends and
//     burner accounts. It is wallet-agnostic and only permitted to mint
//     documents.
//   - Owner Key/Address: The vault identity restricted entirely to signing
//     off on fund withdrawals, ensuring assets can only exit to a
//     hardcoded destination.
//
// ── DOCUMENT TOKEN PERMANENCE ────────────────────────────────────────────
// Minted document tokens are sent to THIS SCRIPT'S OWN ADDRESS, never to
// any external wallet. They are anti-censorship archive records, not a
// currency or collectible - never transferable, never wallet-custodied.
// Once minted here, a document token becomes structurally unspendable by
// anyone, forever: the spend validator below only ever attempts to decode
// a spent UTXO's datum as MasterDatum, which a TokenDatum-shaped value can
// never satisfy. There is no redeemer, no signature, no future action -
// not even by authority - that can move a document token out of this
// address. This is a deliberate, permanent, one-way design choice with no
// escape valve anywhere in this script. A future migration, if ever
// needed, happens via LinkForward/LinkBackward at the registry level
// (chaining to a freshly deployed successor), never by relocating an
// existing document token.
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
//    state nonce, and ensures the accompanying token output embeds a
//    structured, tamper-proof metadata payload (SHA256 hash, version number,
//    data bytes) AND co-locates the actual minted asset with that exact
//    payload, permanently locked at this script's own address.
//
// 3. CIRCUIT-BREAKER LIFECYCLE CONTROLS (`Pause` / `Resume`)
//    Enables the primary authority to immediately freeze all minting
//    behaviors if unexpected conditions arise, providing a secure runtime
//    switch to halt the script's core operations without risking registry
//    state corruption.
//
// 4. SECURE REVENUE MANAGEMENT (`Withdraw`)
//    Implements a locked withdrawal gate requiring an explicit cryptographic
//    signature from the designated Owner Key. It strictly validates that any
//    withdrawn Lovelace matching the requested amount is paid out directly to
//    the unchangeable `owner_address` stored in the contract.
//
// 5. ADMINISTRATIVE MAINTENANCE (`RotateKey`)
//    Allows the root authority to cleanly migrate operational keys
//    (Authority, Operator, or Owner) to new public key hashes dynamically,
//    ensuring smooth rotation without altering code deployments.
//
// 6. BIDIRECTIONAL DEPLOYMENT CHAINING (`LinkForward` / `LinkBackward`)
//    Addresses smart contract immutability by providing a dual-pointer
//    system to migrate or trace older and newer versions of the contract
//    architecture:
//      - `LinkForward`: Permanent pointer sealing a current registry's path
//        forward to its newly deployed successor script.
//      - `LinkBackward`: Permanent pointer allowing a new script to map its
//        lineage backward to its historical ancestral origin.
//    Once written, these slots are permanently locked to establish an
//    un-censorable, two-way cryptographic path of historical system custody
//    on the blockchain.
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
  authority_key: VerificationKey,
  operator_key: VerificationKey,
  owner_key: VerificationKey,
  owner_address: Address,
  nonce: Int,
  is_paused: Bool,
  policy_id: ByteArray,
  asset_name_prefix: ByteArray,
  forward_link: Option<DeploymentChainLink>,
  backward_link: Option<DeploymentChainLink>,
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

// ── Mint Policy Redeemer ─────────────────────────────────────────────────
pub type CreateTokenAction {
  MintToken
  BurnToken
  MintBeacon
}



// ── Helpers ──────────────────────────────────────────────────────────────

fn find_master_input(inputs: List<Input>, own_ref: OutputReference) -> Output {
  expect Some(input) =
    list.find(inputs, fn(i) { i.output_reference == own_ref })
  input.output
}

fn own_script_hash(addr: Address) -> ByteArray {
  when addr.payment_credential is {
    Script(h) -> h
    _ -> fail @"Master UTXO is not locked at a script address - this should never happen"
  }
}

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

fn find_token_output_with_datum(
  outputs: List<Output>,
  policy_id: ByteArray,
  asset_name: ByteArray,
  beacon_policy_id: ByteArray,
  beacon_asset_name: ByteArray,
  script_address: Address,
) -> TokenDatum {
  when outputs is {
    [] -> fail @"Token output co-locating the minted asset with a matching TokenDatum, locked at the registry's own address, not found"
    [head, ..tail] -> {
      let holds_beacon =
        assets.quantity_of(head.value, beacon_policy_id, beacon_asset_name) == 1
      if holds_beacon {
        find_token_output_with_datum(tail, policy_id, asset_name, beacon_policy_id, beacon_asset_name, script_address)
      } else {
        when head.datum is {
          InlineDatum(datum_data) -> {
            expect token_datum: TokenDatum = datum_data
            let holds_asset = assets.quantity_of(head.value, policy_id, asset_name) == 1
            let at_registry_address = head.address == script_address
            if token_datum.policy_id == policy_id && holds_asset && at_registry_address {
              token_datum
            } else {
              find_token_output_with_datum(tail, policy_id, asset_name, beacon_policy_id, beacon_asset_name, script_address)
            }
          }
          _ -> find_token_output_with_datum(tail, policy_id, asset_name, beacon_policy_id, beacon_asset_name, script_address)
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

// ── Spend Validator ──────────────────────────────────────────────────────
validator archive_registry(genesis_ref: OutputReference, beacon_asset_name: ByteArray) {

  spend(
    datum: Option<MasterDatum>,
    redeemer: RegistryAction,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    // ── Non-citizen UTxO sweep path ───────────────────────────────────────
    // UTxOs at this script address with no datum are plain ADA non-citizens
    // (accidentally sent by anyone). They can be swept via SweepFunds.
    // Citizen UTxOs (master UTXO, document token UTxOs) always have datums
    // and are protected by the beacon token check below.
    when datum is {
      None -> {
        // Only SweepFunds redeemer is valid for datum-less UTxOs
        expect SweepFunds { amount, to_address, signature } = redeemer

        // Derive own policy ID from the input being spent
        let own_input = find_master_input(self.inputs, own_ref)
        let own_policy_id = own_script_hash(own_input.address)

        // ── Critical: reject if this UTxO carries any policy token ───────
        // This prevents spending master UTXO or document token UTxOs via
        // this path. Beacon token and document tokens all share own_policy_id.
        // Any UTxO carrying any token under this policy is a citizen and
        // must not be swept.
        expect dict.size(assets.tokens(own_input.value, own_policy_id)) == 0

        // ── Read master UTXO as reference input for key validation ────────
        expect Some(master_ref_input) =
          list.find(
            self.reference_inputs,
            fn(i) {
              assets.quantity_of(i.output.value, own_policy_id, beacon_asset_name) == 1
            },
          )
        expect InlineDatum(datum_data) = master_ref_input.output.datum
        expect master_datum: MasterDatum = datum_data

        // ── Validate signature — any of the three keys may authorize ──────
        let signed_payload =
          bytearray.concat(
            bytearray.concat(
              bytearray.from_int_big_endian(master_datum.nonce, 8),
              "SWEEP_FUNDS",
            ),
            bytearray.from_int_big_endian(amount, 8),
          )

        expect
          verify_ed25519_signature(master_datum.authority_key, signed_payload, signature) ||
          verify_ed25519_signature(master_datum.operator_key, signed_payload, signature) ||
          verify_ed25519_signature(master_datum.owner_key, signed_payload, signature)

        // ── Validate withdrawal output goes to specified address ──────────
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

      Some(old_datum) -> {
        let master_input = find_master_input(self.inputs, own_ref)
        let own_policy_id = own_script_hash(master_input.address)

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

        let new_output =
          find_master_output_by_beacon(self.outputs, own_policy_id, beacon_asset_name)
        let new_datum = datum_from_output(new_output)
        require_beacon_carried_forward(new_output, own_policy_id, beacon_asset_name)

        let minted_assets = assets.tokens(self.mint, old_datum.policy_id)
        trace @"TRACE:MD:minted_assets_not_singleton"
        expect [Pair(asset_name, mint_quantity)] = dict.to_pairs(minted_assets)
        trace @"TRACE:MD:mint_quantity_not_1"
        expect mint_quantity == 1

        let token_output_datum =
          find_token_output_with_datum(
            self.outputs,
            old_datum.policy_id,
            asset_name,
            own_policy_id,
            beacon_asset_name,
            new_output.address,
          )

        // Validate Token Setup
        trace @"TRACE:MD:token_global_id_mismatch"
        expect token_output_datum.cross_chain_global_id == cross_chain_global_id
        trace @"TRACE:MD:token_registry_address_not_empty"
        expect token_output_datum.registry_address == #""
        trace @"TRACE:MD:token_policy_id_mismatch"
        expect token_output_datum.policy_id == old_datum.policy_id
        trace @"TRACE:MD:token_utxo_ref_mismatch"
        expect token_output_datum.source_registry_master_utxo_reference == own_ref

        // Payload Verification
        trace @"TRACE:MD:token_sha256_mismatch"
        expect token_output_datum.sha256_hash == sha256_hash
        trace @"TRACE:MD:token_upload_date_mismatch"
        expect token_output_datum.upload_date == upload_date
        trace @"TRACE:MD:token_version_mismatch"
        expect token_output_datum.version == version
        trace @"TRACE:MD:token_data_mismatch"
        expect token_output_datum.token_data == token_data

        // Validate Master Registry Updates
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

        // Static fields preserved
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

        True
      }

      Pause { nonce, signature } -> {
        expect nonce == old_datum.nonce
        expect old_datum.is_paused == False
        let signed_payload =
          bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "PAUSE")
        expect verify_ed25519_signature(old_datum.authority_key, signed_payload, signature)

        let new_output =
          find_master_output_by_beacon(self.outputs, own_policy_id, beacon_asset_name)
        let new_datum = datum_from_output(new_output)
        require_beacon_carried_forward(new_output, own_policy_id, beacon_asset_name)

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

        True
      }

      Resume { nonce, signature } -> {
        expect nonce == old_datum.nonce
        expect old_datum.is_paused == True
        let signed_payload =
          bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "RESUME")
        expect verify_ed25519_signature(old_datum.authority_key, signed_payload, signature)

        let new_output =
          find_master_output_by_beacon(self.outputs, own_policy_id, beacon_asset_name)
        let new_datum = datum_from_output(new_output)
        require_beacon_carried_forward(new_output, own_policy_id, beacon_asset_name)

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

        let new_output =
          find_master_output_by_beacon(self.outputs, own_policy_id, beacon_asset_name)
        let new_datum = datum_from_output(new_output)
        require_beacon_carried_forward(new_output, own_policy_id, beacon_asset_name)

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

        let new_output =
          find_master_output_by_beacon(self.outputs, own_policy_id, beacon_asset_name)
        let new_datum = datum_from_output(new_output)
        require_beacon_carried_forward(new_output, own_policy_id, beacon_asset_name)

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

        let new_output =
          find_master_output_by_beacon(self.outputs, own_policy_id, beacon_asset_name)
        let new_datum = datum_from_output(new_output)
        require_beacon_carried_forward(new_output, own_policy_id, beacon_asset_name)

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

        True
      }

      // SweepFunds is only valid for None datum UTxOs — reject if datum present
      SweepFunds { .. } -> False
    }
      }
    }
  }

  mint(token_action: CreateTokenAction, policy_id: ByteArray, self: Transaction) {
    when token_action is {
      MintBeacon -> {
        expect list.any(self.inputs, fn(i) { i.output_reference == genesis_ref })

        let minted_assets = assets.tokens(self.mint, policy_id)
        expect [Pair(asset_name, quantity)] = dict.to_pairs(minted_assets)
        expect asset_name == beacon_asset_name
        expect quantity == 1

        True
      }

      MintToken -> {
        let minted_assets = assets.tokens(self.mint, policy_id)
        trace @"TRACE:MT:minted_assets_not_singleton"
        expect [Pair(asset_name, quantity)] = dict.to_pairs(minted_assets)
        trace @"TRACE:MT:quantity_not_1"
        expect quantity == 1

        trace @"TRACE:MT:master_input_not_found"
        expect Some(master_input) =
          list.find(self.inputs, fn(i) { i.output.address.payment_credential == Script(policy_id) })

        trace @"TRACE:MT:master_input_no_inline_datum"
        expect InlineDatum(datum_data) = master_input.output.datum
        trace @"TRACE:MT:master_datum_deserialize_failed"
        expect master_datum: MasterDatum = datum_data

        trace @"TRACE:MT:beacon_not_in_master_input"
        expect assets.quantity_of(
          master_input.output.value,
          policy_id,
          beacon_asset_name,
        ) == 1

        let prefix = master_datum.asset_name_prefix
        let prefix_len = bytearray.length(prefix)
        trace @"TRACE:MT:asset_name_prefix_mismatch"
        expect bytearray.take(asset_name, prefix_len) == prefix

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

        True
      }

      BurnToken -> False
    }
  }
}
