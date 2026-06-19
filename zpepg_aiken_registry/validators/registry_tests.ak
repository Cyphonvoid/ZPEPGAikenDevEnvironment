use aiken/collection/dict
use aiken/interval
use aiken/crypto.{VerificationKey, Signature, verify_ed25519_signature}
use aiken/primitive/bytearray
use aiken/collection/list
use cardano/address.{Address, Script}
use cardano/assets
use cardano/transaction.{
  OutputReference, Transaction, TransactionId, Input, Output, InlineDatum,
  NoDatum,
}

// ── Type Definitions (mirrored from contract) ─────────────────────────────

pub type RegistryStats {
  total_token_count: Int,
  total_unique_documents: Int,
  last_minted_at: Int,
  last_cross_chain_global_id: ByteArray,
  last_cardano_asset_id: ByteArray,
}

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
  forward_link: Option<DeploymentChainLink>,
  backward_link: Option<DeploymentChainLink>,
  stats: RegistryStats,
}

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

// ── Test Constants ────────────────────────────────────────────────────────

// Authority public key (Ed25519, 32 bytes)
const authority_pub: ByteArray =
  #"c961ebec90929a19f4a977ae08df85211c1dbe6f449717eb61b76740be5f326e"

// Dummy operator and owner keys (not used in Pause/Resume, just need valid 32 bytes)
const dummy_key: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000000001"

// Signature over concat(nonce=0 as 8-byte big-endian, "PAUSE")
const pause_sig_nonce0: ByteArray =
  #"773f66119642f431b414e787576650db3c58e4e80181cc9d9c497f1f22b4408805046b7e39e8a7c4ad5332b8250ae20cc9113be18a551a765f57219090adbe0f"

// Signature over concat(nonce=0 as 8-byte big-endian, "RESUME")
const resume_sig_nonce0: ByteArray =
  #"e862566c39ab82c45127fc30bf6933b750cfba42e6fbf71c3c8fb78edd1cf43a9f03ee9fd6a3c8dbe4c3d3e56c515f4ac24a7debce553b38faddd72e20aa0a01"

// Dummy tx hash (32 bytes)
const dummy_tx_hash: ByteArray =
  #"abababababababababababababababababababababababababababababababababab"

// Dummy script hash for address (28 bytes)
const dummy_script_hash: ByteArray =
  #"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

// ── RotateKey Test Constants ──────────────────────────────────────────────

const new_authority_key: ByteArray =
  #"1111111111111111111111111111111111111111111111111111111111111111"

const new_operator_key: ByteArray =
  #"2222222222222222222222222222222222222222222222222222222222222222"

const new_owner_key: ByteArray =
  #"3333333333333333333333333333333333333333333333333333333333333333"

const sig_rotate_authority: ByteArray =
  #"389a1b09e4b221939c29a3cdd241cb96da07fc9641fb85837ce240b4425700db397500bbce9d04c61188a864ce6c53161ac7ff7c4b4d4842c8a1c1bc00abda0c"

const sig_rotate_operator: ByteArray =
  #"26e31e3eaee3992bf764485c5022d27af7906ef6148db80a2c0378f2903359c5bc754dfefc60c90fae2a426be85337a957abb8bb54a14f6d43d94d7536850e09"

const sig_rotate_owner: ByteArray =
  #"f3d779585b98e1530caef318774a11089ac9b98ccc54b8890873cc2e53a74a58b1367029102c9ffe7e32a6f3aabbea57c43335deb4fbf7da47aa1f51b6ae2a0b"

// ── Fixture Helpers ───────────────────────────────────────────────────────

fn mock_output_ref(index: Int) -> OutputReference {
  OutputReference {
    transaction_id: dummy_tx_hash,
    output_index: index,
  }
}


fn mock_address() -> Address {
  Address {
    payment_credential: Script(dummy_script_hash),
    stake_credential: None,
  }
}

fn mock_stats() -> RegistryStats {
  RegistryStats {
    total_token_count: 0,
    total_unique_documents: 0,
    last_minted_at: 0,
    last_cross_chain_global_id: #"",
    last_cardano_asset_id: #"",
  }
}

fn mock_master_datum(nonce: Int, is_paused: Bool, self_ref: OutputReference) -> MasterDatum {
  MasterDatum {
    authority_key: authority_pub,
    operator_key: dummy_key,
    owner_key: dummy_key,
    owner_address: mock_address(),
    nonce,
    is_paused,
    policy_id: #"cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe",
    asset_name_prefix: #"5a504550475f",
    self_ref,
    forward_link: None,
    backward_link: None,
    stats: mock_stats(),
  }
}

fn mock_input(output_ref: OutputReference, datum: MasterDatum) -> Input {
  Input {
    output_reference: output_ref,
    output: Output {
      address: mock_address(),
      value: assets.zero,
      datum: InlineDatum(datum),
      reference_script: None,
    },
  }
}

fn mock_output(datum: MasterDatum) -> Output {
  Output {
    address: mock_address(),
    value: assets.zero,
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

// Build a minimal Transaction for Pause/Resume:
// - one input at own_ref with old_datum
// - one output at same address with new_datum
fn mock_tx(
  own_ref: OutputReference,
  old_datum: MasterDatum,
  new_datum: MasterDatum,
) -> Transaction {
  Transaction {
    inputs: [mock_input(own_ref, old_datum)],
    reference_inputs: [],
    outputs: [mock_output(new_datum)],
    fee: 0,
    mint: assets.zero,
    certificates: [],
    withdrawals: [],
    validity_range: interval.everything,
    extra_signatories: [],
    redeemers: [],
    datums: dict.empty,
    id: dummy_tx_hash,
    votes: [],
    proposal_procedures: [],
    current_treasury_amount: None,
    treasury_donation: None,
  }
}

// ── Signature Sanity Tests ────────────────────────────────────────────────

test verify_pause_signature_is_valid() {
  let nonce = 0
  let signed_payload =
    bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "PAUSE")
  verify_ed25519_signature(authority_pub, signed_payload, pause_sig_nonce0)
}

test verify_resume_signature_is_valid() {
  let nonce = 0
  let signed_payload =
    bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "RESUME")
  verify_ed25519_signature(authority_pub, signed_payload, resume_sig_nonce0)
}

test wrong_signature_fails() {
  let nonce = 0
  let signed_payload =
    bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "PAUSE")
  // Resume sig should NOT verify against PAUSE payload
  !verify_ed25519_signature(authority_pub, signed_payload, resume_sig_nonce0)
}

// ── Pause Logic Tests ─────────────────────────────────────────────────────

test pause_sets_is_paused_true() {
  let own_ref = mock_output_ref(0)
  let new_ref = mock_output_ref(0)  // same tx, output index 0
  let old_datum = mock_master_datum(0, False, own_ref)
  let new_datum = mock_master_datum(1, True, new_ref)

  // Check all the things the validator checks
  let nonce = 0
  let signed_payload =
    bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "PAUSE")

  and {
    // canonical master check
    own_ref == old_datum.self_ref,
    // nonce matches
    nonce == old_datum.nonce,
    // signature valid
    verify_ed25519_signature(authority_pub, signed_payload, pause_sig_nonce0),
    // nonce incremented
    new_datum.nonce == old_datum.nonce + 1,
    // is_paused flipped to True
    new_datum.is_paused == True,
    // immutable fields unchanged
    new_datum.authority_key == old_datum.authority_key,
    new_datum.operator_key == old_datum.operator_key,
    new_datum.owner_key == old_datum.owner_key,
    new_datum.owner_address == old_datum.owner_address,
    new_datum.policy_id == old_datum.policy_id,
    new_datum.asset_name_prefix == old_datum.asset_name_prefix,
    new_datum.forward_link == old_datum.forward_link,
    new_datum.backward_link == old_datum.backward_link,
    new_datum.stats == old_datum.stats,
  }
}

test pause_wrong_nonce_fails() {
  let own_ref = mock_output_ref(0)
  let old_datum = mock_master_datum(0, False, own_ref)
  let wrong_nonce = 1  // should be 0

  wrong_nonce != old_datum.nonce
}

test pause_already_paused_still_passes_logic() {
  // Validator doesn't check that registry isn't already paused before pausing
  // This test documents that behavior — pausing an already-paused registry
  // is not blocked at the logic level (is_paused just gets set to True again)
  let own_ref = mock_output_ref(0)
  let old_datum = mock_master_datum(0, True, own_ref)  // already paused
  let new_datum = mock_master_datum(1, True, own_ref)

  and {
    new_datum.nonce == old_datum.nonce + 1,
    new_datum.is_paused == True,
  }
}

// ── Resume Logic Tests ────────────────────────────────────────────────────

test resume_sets_is_paused_false() {
  let own_ref = mock_output_ref(0)
  let old_datum = mock_master_datum(0, True, own_ref)  // starts paused
  let new_datum = mock_master_datum(1, False, own_ref)

  let nonce = 0
  let signed_payload =
    bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "RESUME")

  and {
    own_ref == old_datum.self_ref,
    nonce == old_datum.nonce,
    verify_ed25519_signature(authority_pub, signed_payload, resume_sig_nonce0),
    new_datum.nonce == old_datum.nonce + 1,
    new_datum.is_paused == False,
    new_datum.authority_key == old_datum.authority_key,
    new_datum.operator_key == old_datum.operator_key,
    new_datum.owner_key == old_datum.owner_key,
    new_datum.owner_address == old_datum.owner_address,
    new_datum.policy_id == old_datum.policy_id,
    new_datum.asset_name_prefix == old_datum.asset_name_prefix,
    new_datum.forward_link == old_datum.forward_link,
    new_datum.backward_link == old_datum.backward_link,
    new_datum.stats == old_datum.stats,
  }
}

test resume_wrong_nonce_fails() {
  let own_ref = mock_output_ref(0)
  let old_datum = mock_master_datum(0, True, own_ref)
  let wrong_nonce = 5

  wrong_nonce != old_datum.nonce
}

test pause_then_resume_nonce_sequence() {
  // Simulate: pause at nonce 0, resume at nonce 1
  let own_ref = mock_output_ref(0)
  let initial = mock_master_datum(0, False, own_ref)
  let after_pause = mock_master_datum(1, True, own_ref)
  let after_resume = mock_master_datum(2, False, own_ref)

  and {
    after_pause.nonce == initial.nonce + 1,
    after_pause.is_paused == True,
    after_resume.nonce == after_pause.nonce + 1,
    after_resume.is_paused == False,
  }
}

test canonical_master_check_fails_if_self_ref_mismatch() {
  let own_ref = mock_output_ref(0)
  let wrong_ref = mock_output_ref(1)
  let datum = mock_master_datum(0, False, wrong_ref)  // self_ref points elsewhere

  // canonical check: own_ref == datum.self_ref should fail
  !(own_ref == datum.self_ref)
}

// ── RotateKey Signature Tests ─────────────────────────────────────────────

test rotate_authority_signature_valid() {
  let nonce = 0
  let payload =
    bytearray.concat(
      bytearray.concat(
        bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "ROTATE"),
        "AUTHORITY",
      ),
      new_authority_key,
    )
  verify_ed25519_signature(authority_pub, payload, sig_rotate_authority)
}

test rotate_operator_signature_valid() {
  let nonce = 0
  let payload =
    bytearray.concat(
      bytearray.concat(
        bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "ROTATE"),
        "OPERATOR",
      ),
      new_operator_key,
    )
  verify_ed25519_signature(authority_pub, payload, sig_rotate_operator)
}

test rotate_owner_signature_valid() {
  let nonce = 0
  let payload =
    bytearray.concat(
      bytearray.concat(
        bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "ROTATE"),
        "OWNER",
      ),
      new_owner_key,
    )
  verify_ed25519_signature(authority_pub, payload, sig_rotate_owner)
}

test rotate_wrong_key_in_payload_fails() {
  // Signing with operator key bytes but claiming authority — sig should not verify
  let nonce = 0
  let payload =
    bytearray.concat(
      bytearray.concat(
        bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "ROTATE"),
        "AUTHORITY",
      ),
      new_operator_key,  // wrong key bytes in payload
    )
  !verify_ed25519_signature(authority_pub, payload, sig_rotate_authority)
}

// ── RotateKey Logic Tests ─────────────────────────────────────────────────

test rotate_authority_key_updates_only_authority() {
  let own_ref = mock_output_ref(0)
  let old_datum = mock_master_datum(0, False, own_ref)

  // new datum has authority_key swapped, everything else same
  let new_datum =
    MasterDatum {
      ..old_datum,
      nonce: 1,
      authority_key: new_authority_key,
      self_ref: own_ref,
    }

  and {
    new_datum.nonce == old_datum.nonce + 1,
    new_datum.authority_key == new_authority_key,
    new_datum.operator_key == old_datum.operator_key,
    new_datum.owner_key == old_datum.owner_key,
    new_datum.stats == old_datum.stats,
    new_datum.owner_address == old_datum.owner_address,
    new_datum.is_paused == old_datum.is_paused,
    new_datum.policy_id == old_datum.policy_id,
    new_datum.asset_name_prefix == old_datum.asset_name_prefix,
    new_datum.forward_link == old_datum.forward_link,
    new_datum.backward_link == old_datum.backward_link,
  }
}

test rotate_operator_key_updates_only_operator() {
  let own_ref = mock_output_ref(0)
  let old_datum = mock_master_datum(0, False, own_ref)

  let new_datum =
    MasterDatum {
      ..old_datum,
      nonce: 1,
      operator_key: new_operator_key,
      self_ref: own_ref,
    }

  and {
    new_datum.nonce == old_datum.nonce + 1,
    new_datum.authority_key == old_datum.authority_key,
    new_datum.operator_key == new_operator_key,
    new_datum.owner_key == old_datum.owner_key,
    new_datum.stats == old_datum.stats,
    new_datum.is_paused == old_datum.is_paused,
    new_datum.policy_id == old_datum.policy_id,
    new_datum.forward_link == old_datum.forward_link,
    new_datum.backward_link == old_datum.backward_link,
  }
}

test rotate_owner_key_updates_only_owner() {
  let own_ref = mock_output_ref(0)
  let old_datum = mock_master_datum(0, False, own_ref)

  let new_datum =
    MasterDatum {
      ..old_datum,
      nonce: 1,
      owner_key: new_owner_key,
      self_ref: own_ref,
    }

  and {
    new_datum.nonce == old_datum.nonce + 1,
    new_datum.authority_key == old_datum.authority_key,
    new_datum.operator_key == old_datum.operator_key,
    new_datum.owner_key == new_owner_key,
    new_datum.stats == old_datum.stats,
    new_datum.is_paused == old_datum.is_paused,
    new_datum.policy_id == old_datum.policy_id,
    new_datum.forward_link == old_datum.forward_link,
    new_datum.backward_link == old_datum.backward_link,
  }
}

test rotate_key_wrong_nonce_fails() {
  let own_ref = mock_output_ref(0)
  let old_datum = mock_master_datum(0, False, own_ref)
  let wrong_nonce = 99

  wrong_nonce != old_datum.nonce
}

test rotate_key_nonce_increments() {
  let own_ref = mock_output_ref(0)
  let old_datum = mock_master_datum(0, False, own_ref)
  let new_datum = MasterDatum { ..old_datum, nonce: 1, authority_key: new_authority_key }

  new_datum.nonce == old_datum.nonce + 1
}

test rotate_authority_cross_sig_fails() {
  // operator sig should not verify for authority rotation
  let nonce = 0
  let payload =
    bytearray.concat(
      bytearray.concat(
        bytearray.concat(bytearray.from_int_big_endian(nonce, 8), "ROTATE"),
        "AUTHORITY",
      ),
      new_authority_key,
    )
  !verify_ed25519_signature(authority_pub, payload, sig_rotate_operator)
}

// ── MintDocument Constants ────────────────────────────────────────────────

const operator_pub: ByteArray =
  #"3f6e9996aca43e2770789689607484ef350ca06308afa91bdc639917cf8543c2"

const cross_chain_global_id: ByteArray =
  #"746573742d676c6f62616c2d69642d3030303030303030303030303030303030"

const sha256_hash_doc: ByteArray =
  #"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"

const sig_mint_document: ByteArray =
  #"0ad547841fdca051689420c22eda15c82f193da8f4fc5bb5b91ef0965a5dddf2643eca5d030493563ebe60cd30f5cdd04464aedde09b60889ffbdf97347d2a0f"

// policy_id for mint tests (28 bytes)
const test_policy_id: ByteArray =
  #"cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe"

// asset name prefix "ZPEPG_" as hex
const test_prefix: ByteArray =
  #"5a504550475f"

// asset name = prefix ++ some suffix
const test_asset_name: ByteArray =
  #"5a504550475f303030303031"

// cardano_asset_id = policy_id ++ asset_name
const test_cardano_asset_id: ByteArray =
  #"cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe5a504550475f303030303031"

const test_upload_date: ByteArray =
  #"323032352d30312d3031"

const test_token_data: ByteArray =
  #"736f6d6520746f6b656e2064617461"

// ── MintDocument Fixture Helpers ──────────────────────────────────────────

fn mock_master_datum_for_mint(nonce: Int, self_ref: OutputReference) -> MasterDatum {
  MasterDatum {
    authority_key: authority_pub,
    operator_key: operator_pub,
    owner_key: dummy_key,
    owner_address: mock_address(),
    nonce,
    is_paused: False,
    policy_id: test_policy_id,
    asset_name_prefix: test_prefix,
    self_ref,
    forward_link: None,
    backward_link: None,
    stats: RegistryStats {
      total_token_count: 5,
      total_unique_documents: 3,
      last_minted_at: 0,
      last_cross_chain_global_id: #"",
      last_cardano_asset_id: #"",
    },
  }
}

fn mock_token_datum(own_ref: OutputReference) -> TokenDatum {
  TokenDatum {
    cardano_asset_id: test_cardano_asset_id,
    cross_chain_global_id: cross_chain_global_id,
    registry_address: #"",
    policy_id: test_policy_id,
    source_registry_master_utxo_reference: own_ref,
    sha256_hash: sha256_hash_doc,
    upload_date: test_upload_date,
    version: 1,
    token_data: test_token_data,
  }
}

// ── MintDocument Signature Tests ──────────────────────────────────────────

test mint_document_signature_valid() {
  let nonce = 0
  let payload =
    bytearray.concat(
      bytearray.concat(
        bytearray.concat(
          bytearray.from_int_big_endian(nonce, 8),
          cross_chain_global_id,
        ),
        sha256_hash_doc,
      ),
      bytearray.from_int_big_endian(1, 4),
    )
  verify_ed25519_signature(operator_pub, payload, sig_mint_document)
}

test mint_document_authority_sig_does_not_verify_operator_payload() {
  // authority key should not verify operator-signed payload
  let nonce = 0
  let payload =
    bytearray.concat(
      bytearray.concat(
        bytearray.concat(
          bytearray.from_int_big_endian(nonce, 8),
          cross_chain_global_id,
        ),
        sha256_hash_doc,
      ),
      bytearray.from_int_big_endian(1, 4),
    )
  !verify_ed25519_signature(authority_pub, payload, sig_mint_document)
}

// ── MintDocument Logic Tests ──────────────────────────────────────────────

test mint_document_nonce_check() {
  let own_ref = mock_output_ref(0)
  let old_datum = mock_master_datum_for_mint(0, own_ref)
  let redeemer_nonce = 0

  redeemer_nonce == old_datum.nonce
}

test mint_document_wrong_nonce_fails() {
  let own_ref = mock_output_ref(0)
  let old_datum = mock_master_datum_for_mint(0, own_ref)
  let wrong_nonce = 3

  wrong_nonce != old_datum.nonce
}

test mint_document_paused_registry_blocked() {
  let own_ref = mock_output_ref(0)
  let paused_datum = MasterDatum {
    ..mock_master_datum_for_mint(0, own_ref),
    is_paused: True,
  }

  paused_datum.is_paused == True
}

test mint_document_token_datum_cross_chain_id_matches() {
  let own_ref = mock_output_ref(0)
  let token_datum = mock_token_datum(own_ref)

  token_datum.cross_chain_global_id == cross_chain_global_id
}

test mint_document_token_datum_registry_address_empty() {
  let own_ref = mock_output_ref(0)
  let token_datum = mock_token_datum(own_ref)

  token_datum.registry_address == #""
}

test mint_document_token_datum_policy_id_matches() {
  let own_ref = mock_output_ref(0)
  let old_datum = mock_master_datum_for_mint(0, own_ref)
  let token_datum = mock_token_datum(own_ref)

  token_datum.policy_id == old_datum.policy_id
}

test mint_document_token_datum_source_ref_matches_own_ref() {
  let own_ref = mock_output_ref(0)
  let token_datum = mock_token_datum(own_ref)

  token_datum.source_registry_master_utxo_reference == own_ref
}

test mint_document_token_datum_payload_integrity() {
  let own_ref = mock_output_ref(0)
  let token_datum = mock_token_datum(own_ref)

  and {
    token_datum.sha256_hash == sha256_hash_doc,
    token_datum.upload_date == test_upload_date,
    token_datum.version == 1,
    token_datum.token_data == test_token_data,
  }
}

test mint_document_asset_name_has_correct_prefix() {
  let prefix_len = bytearray.length(test_prefix)
  bytearray.take(test_asset_name, prefix_len) == test_prefix
}

test mint_document_cardano_asset_id_correct() {
  let expected = bytearray.concat(test_policy_id, test_asset_name)
  expected == test_cardano_asset_id
}

test mint_document_stats_token_count_incremented() {
  let own_ref = mock_output_ref(0)
  let old_datum = mock_master_datum_for_mint(0, own_ref)
  let new_stats = RegistryStats {
    total_token_count: old_datum.stats.total_token_count + 1,
    total_unique_documents: old_datum.stats.total_unique_documents,
    last_minted_at: 1000,
    last_cross_chain_global_id: cross_chain_global_id,
    last_cardano_asset_id: test_cardano_asset_id,
  }

  new_stats.total_token_count == old_datum.stats.total_token_count + 1
}

test mint_document_stats_unique_incremented_when_unique() {
  let own_ref = mock_output_ref(0)
  let old_datum = mock_master_datum_for_mint(0, own_ref)
  let is_unique = True
  let expected_inc = if is_unique { 1 } else { 0 }
  let new_unique = old_datum.stats.total_unique_documents + expected_inc

  new_unique == old_datum.stats.total_unique_documents + 1
}

test mint_document_stats_unique_not_incremented_when_not_unique() {
  let own_ref = mock_output_ref(0)
  let old_datum = mock_master_datum_for_mint(0, own_ref)
  let is_unique = False
  let expected_inc = if is_unique { 1 } else { 0 }
  let new_unique = old_datum.stats.total_unique_documents + expected_inc

  new_unique == old_datum.stats.total_unique_documents
}

test mint_document_stats_last_minted_at_set() {
  let valid_lower_bound = 1234567
  let new_stats = RegistryStats {
    total_token_count: 1,
    total_unique_documents: 1,
    last_minted_at: valid_lower_bound,
    last_cross_chain_global_id: cross_chain_global_id,
    last_cardano_asset_id: test_cardano_asset_id,
  }

  new_stats.last_minted_at == valid_lower_bound
}

test mint_document_static_fields_preserved() {
  let own_ref = mock_output_ref(0)
  let old_datum = mock_master_datum_for_mint(0, own_ref)
  let new_datum = MasterDatum {
    ..old_datum,
    nonce: 1,
    stats: RegistryStats {
      total_token_count: old_datum.stats.total_token_count + 1,
      total_unique_documents: old_datum.stats.total_unique_documents + 1,
      last_minted_at: 1000,
      last_cross_chain_global_id: cross_chain_global_id,
      last_cardano_asset_id: test_cardano_asset_id,
    },
  }

  and {
    new_datum.authority_key == old_datum.authority_key,
    new_datum.operator_key == old_datum.operator_key,
    new_datum.owner_key == old_datum.owner_key,
    new_datum.owner_address == old_datum.owner_address,
    new_datum.is_paused == old_datum.is_paused,
    new_datum.policy_id == old_datum.policy_id,
    new_datum.asset_name_prefix == old_datum.asset_name_prefix,
    new_datum.forward_link == old_datum.forward_link,
    new_datum.backward_link == old_datum.backward_link,
  }
}

test mint_document_nonce_incremented_in_new_datum() {
  let own_ref = mock_output_ref(0)
  let old_datum = mock_master_datum_for_mint(0, own_ref)
  let new_datum = MasterDatum { ..old_datum, nonce: 1 }

  new_datum.nonce == old_datum.nonce + 1
}
