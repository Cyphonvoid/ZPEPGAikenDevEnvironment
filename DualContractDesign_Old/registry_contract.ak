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
// This version replaces self-referential datum-field checking with a
// beacon token (see beacon_policy.ak): a single native asset, minted
// exactly once at genesis under a one-shot policy, that must be carried
// forward into every successor master UTXO. "The canonical master UTXO" is
// defined as "whichever UTXO holds this exact token" — a ledger-enforced,
// non-copyable fact, since eUTXO guarantees a given native asset unit can
// only ever sit in one place at a time. Decoys cannot acquire the beacon:
// they cannot mint a copy (the policy cannot fire twice, ever, for anyone),
// and they cannot obtain the existing unit without spending the real master
// UTXO, which requires the real signing keys.
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
//    data bytes).
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

  // ── BEACON IDENTITY ─────────────────────────────────────────────────────
  // The native asset that marks this UTXO as canonical. Minted exactly once
  // at genesis by beacon_policy.ak. Every spend branch below requires this
  // exact unit to be present in the new master output's Value — see
  // require_beacon_carried_forward. These two fields are immutable for the
  // lifetime of a given deployment; they are never reassigned by any
  // redeemer.
  beacon_policy_id: ByteArray,
  beacon_asset_name: ByteArray,

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

// Finds the new master UTXO output by beacon-token membership rather than
// by address match. This is the discovery primitive that replaces self_ref:
// "the new master output" is now defined as "whichever output in this
// transaction holds the beacon," which is unambiguous regardless of how
// many decoy outputs to the same script address might also exist in this
// transaction or sit unspent elsewhere at the address.
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
            // Requires the candidate output to ACTUALLY HOLD the minted
            // asset, not merely carry a correctly-shaped TokenDatum
            // claiming to describe it. Without this, an output with a
            // convincing-but-fake TokenDatum and zero real tokens could
            // be mistaken for the genuine token output, while the real
            // asset silently lands somewhere else undocumented in the
            // same transaction. Mirrors require_beacon_carried_forward's
            // exact pattern - presence in the Value, not just datum
            // content, is what establishes "this is the real one."
            let holds_asset = assets.quantity_of(head.value, policy_id, asset_name) == 1
            // Requires the candidate output to sit AT THE REGISTRY'S OWN
            // SCRIPT ADDRESS. Document tokens are permanent, anti-censorship
            // archive records, never wallet-custodied or transferable -
            // they are minted directly into permanent script custody and
            // stay there forever. (They become structurally unspendable
            // by anyone, including authority/operator/owner, the moment
            // they land here: this validator's spend entrypoint only ever
            // attempts to decode a spent UTXO's datum as MasterDatum,
            // which a TokenDatum-shaped value can never satisfy - so no
            // redeemer, no signature, no future action can ever move a
            // document token out of this address. This is a one-way,
            // structurally permanent lock, not merely a policy choice.)
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

// Requires that the beacon token is present in the given output's Value,
// in exactly the quantity 1, under the policy_id/asset_name recorded in
// old_datum. Called in every spend branch to guarantee the beacon is
// always carried forward into the successor master UTXO — never dropped,
// never duplicated, never left behind.
fn require_beacon_carried_forward(output: Output, old_datum: MasterDatum) {
  expect assets.quantity_of(
    output.value,
    old_datum.beacon_policy_id,
    old_datum.beacon_asset_name,
  ) == 1
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

    // NOTE: There is deliberately no canonical-master self-reference check
    // here. Canonicality is established by the beacon token: this branch
    // is only reachable by spending whichever UTXO was selected as input,
    // and every redeemer below independently requires the beacon to be
    // present in both the spent input's context (implicitly, since the
    // input is whatever was selected) and explicitly carried forward into
    // the new output via require_beacon_carried_forward. A decoy lacking
    // the beacon can still be spent if someone controls matching keys for
    // it, but it can never produce a new output that satisfies
    // require_beacon_carried_forward unless the real beacon is sacrificed
    // into it — which would require spending the real master UTXO.

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
        let new_output =
          find_master_output_by_beacon(
            self.outputs,
            old_datum.beacon_policy_id,
            old_datum.beacon_asset_name,
          )
        let new_datum = datum_from_output(new_output)
        require_beacon_carried_forward(new_output, old_datum)

        // asset_name comes from self.mint - the transaction's own literal
        // minting field - rather than from any candidate output's datum,
        // since trusting a datum-supplied asset_name to then go find "the"
        // output with that datum would be circular and defeats the point
        // of the presence check inside find_token_output_with_datum.
        let minted_assets = assets.tokens(self.mint, old_datum.policy_id)
        expect [Pair(asset_name, mint_quantity)] = dict.to_pairs(minted_assets)
        expect mint_quantity == 1

        let token_output_datum =
          find_token_output_with_datum(
            self.outputs,
            old_datum.policy_id,
            asset_name,
            old_datum.beacon_policy_id,
            old_datum.beacon_asset_name,
            new_output.address,
          )

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
        expect new_datum.beacon_policy_id == old_datum.beacon_policy_id
        expect new_datum.beacon_asset_name == old_datum.beacon_asset_name
        expect new_datum.forward_link == old_datum.forward_link
        expect new_datum.backward_link == old_datum.backward_link

        True
      }

      Pause { nonce, signature } -> {
        expect nonce == old_datum.nonce
        let signed_payload =
          bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "PAUSE")
        expect verify_ed25519_signature(old_datum.authority_key, signed_payload, signature)

        let new_output =
          find_master_output_by_beacon(
            self.outputs,
            old_datum.beacon_policy_id,
            old_datum.beacon_asset_name,
          )
        let new_datum = datum_from_output(new_output)
        require_beacon_carried_forward(new_output, old_datum)

        expect new_datum.nonce == old_datum.nonce + 1
        expect new_datum.is_paused == True

        expect new_datum.stats == old_datum.stats
        expect new_datum.authority_key == old_datum.authority_key
        expect new_datum.operator_key == old_datum.operator_key
        expect new_datum.owner_key == old_datum.owner_key
        expect new_datum.owner_address == old_datum.owner_address
        expect new_datum.policy_id == old_datum.policy_id
        expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
        expect new_datum.beacon_policy_id == old_datum.beacon_policy_id
        expect new_datum.beacon_asset_name == old_datum.beacon_asset_name
        expect new_datum.forward_link == old_datum.forward_link
        expect new_datum.backward_link == old_datum.backward_link

        True
      }

      Resume { nonce, signature } -> {
        expect nonce == old_datum.nonce
        let signed_payload =
          bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "RESUME")
        expect verify_ed25519_signature(old_datum.authority_key, signed_payload, signature)

        let new_output =
          find_master_output_by_beacon(
            self.outputs,
            old_datum.beacon_policy_id,
            old_datum.beacon_asset_name,
          )
        let new_datum = datum_from_output(new_output)
        require_beacon_carried_forward(new_output, old_datum)

        expect new_datum.nonce == old_datum.nonce + 1
        expect new_datum.is_paused == False

        expect new_datum.stats == old_datum.stats
        expect new_datum.authority_key == old_datum.authority_key
        expect new_datum.operator_key == old_datum.operator_key
        expect new_datum.owner_key == old_datum.owner_key
        expect new_datum.owner_address == old_datum.owner_address
        expect new_datum.policy_id == old_datum.policy_id
        expect new_datum.asset_name_prefix == old_datum.asset_name_prefix
        expect new_datum.beacon_policy_id == old_datum.beacon_policy_id
        expect new_datum.beacon_asset_name == old_datum.beacon_asset_name
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

        let new_output =
          find_master_output_by_beacon(
            self.outputs,
            old_datum.beacon_policy_id,
            old_datum.beacon_asset_name,
          )
        let new_datum = datum_from_output(new_output)
        require_beacon_carried_forward(new_output, old_datum)

        expect new_datum.nonce == old_datum.nonce + 1

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
        expect new_datum.beacon_policy_id == old_datum.beacon_policy_id
        expect new_datum.beacon_asset_name == old_datum.beacon_asset_name
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
          find_master_output_by_beacon(
            self.outputs,
            old_datum.beacon_policy_id,
            old_datum.beacon_asset_name,
          )
        let new_datum = datum_from_output(new_output)
        require_beacon_carried_forward(new_output, old_datum)

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
        expect new_datum.beacon_policy_id == old_datum.beacon_policy_id
        expect new_datum.beacon_asset_name == old_datum.beacon_asset_name
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

        let new_output =
          find_master_output_by_beacon(
            self.outputs,
            old_datum.beacon_policy_id,
            old_datum.beacon_asset_name,
          )
        let new_datum = datum_from_output(new_output)
        require_beacon_carried_forward(new_output, old_datum)

        expect new_datum.nonce == old_datum.nonce + 1

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
        expect new_datum.beacon_policy_id == old_datum.beacon_policy_id
        expect new_datum.beacon_asset_name == old_datum.beacon_asset_name

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

        let new_output =
          find_master_output_by_beacon(
            self.outputs,
            old_datum.beacon_policy_id,
            old_datum.beacon_asset_name,
          )
        let new_datum = datum_from_output(new_output)
        require_beacon_carried_forward(new_output, old_datum)

        expect new_datum.nonce == old_datum.nonce + 1

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
        expect new_datum.beacon_policy_id == old_datum.beacon_policy_id
        expect new_datum.beacon_asset_name == old_datum.beacon_asset_name

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

        // Confirm the spent master input is in fact carrying the beacon —
        // i.e. it's the canonical master UTXO, not a decoy parked at the
        // same script address. A decoy could in principle have a matching
        // payment_credential (same script hash) but, lacking the beacon
        // unit in its Value, fails here.
        expect assets.quantity_of(
          master_input.output.value,
          master_datum.beacon_policy_id,
          master_datum.beacon_asset_name,
        ) == 1

        let prefix = master_datum.asset_name_prefix
        let prefix_len = bytearray.length(prefix)
        expect bytearray.take(asset_name, prefix_len) == prefix

        let token_output_datum =
          find_token_output_with_datum(
            self.outputs,
            policy_id,
            asset_name,
            master_datum.beacon_policy_id,
            master_datum.beacon_asset_name,
            master_input.output.address,
          )

        let expected_asset_id = bytearray.concat(policy_id, asset_name)
        expect token_output_datum.cardano_asset_id == expected_asset_id

        True
      }

      BurnToken -> False
    }
  }
}
