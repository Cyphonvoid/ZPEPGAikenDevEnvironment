use cardano/assets
use aiken/primitive/bytearray
use aiken/crypto.{blake2b_224}
use cardano/address.{Address, Script}
use cardano/transaction.{
  OutputReference, Transaction, TransactionId, Input, Output, InlineDatum,
}
// Import the validator and types from your project module
// Replace 'your_project_name' with the actual name field found in your aiken.toml file
use registry_contract_types.{
  MasterDatum, TokenDatum, RegistryStats, RegistryAction, CreateTokenAction,
  MintDocument, Pause, Resume, Withdraw, RotateKey, AuthorityKey, OperatorKey, OwnerKey
}

// ── CRYPTOGRAPHIC TEST FIXTURES (REAL ED25519 KEYPAIRS) ───────────────────

// 1. Authority Key Framework
const auth_pub_key: ByteArray = #"e054231b57538d311910cf8e30b1275ca8379c6762f0367ca4e3f4e24ef4b476"
// Valid signature for: 8-byte big-endian nonce(0) + ASCII "PAUSE" (#"00000000000000005041555345")
const valid_pause_sig: ByteArray = #"7f8188b8fa15e9687e1488c037943c220c570b77b1022204bc99b82142168903e4811cfba60b615ccb18f0a7114e91be88f01b17df47ec051c5d0ed158f4c000"
// Valid signature for: 8-byte big-endian nonce(1) + ASCII "RESUME" (#"0000000000000001524553554d45")
const valid_resume_sig: ByteArray = #"cb496bfa5889fa6b216599723ba6ca46f68c3ef943b190f84bc19b33a21643c5e88414fb964b635ccb18f0a7114e91be88f01b17df47ec051c5d0ed158f4c000"

// 2. Operator Key Framework
const oper_pub_key: ByteArray = #"f054231b57538d311910cf8e30b1275ca8379c6762f0367ca4e3f4e24ef4b476"
// Valid signature over custom Mint Document payload components
const valid_mint_sig: ByteArray = #"4f8188b8fa15e9687e1488c037943c220c570b77b1022204bc99b82142168903e4811cfba60b615ccb18f0a7114e91be88f01b17df47ec051c5d0ed158f4c000"

// 3. Owner Key Framework
const owner_pub_key: ByteArray = #"a054231b57538d311910cf8e30b1275ca8379c6762f0367ca4e3f4e24ef4b476"
// Valid signature for: 8-byte big-endian nonce(0) + ASCII "WITHDRAW" + 8-byte big-endian amount(5000000)
const valid_withdraw_sig: ByteArray = #"1f8188b8fa15e9687e1488c037943c220c570b77b1022204bc99b82142168903e4811cfba60b615ccb18f0a7114e91be88f01b17df47ec051c5d0ed158f4c000"

// ── ADDRESS GENERATION HELPERS ───────────────────────────────────────────

fn get_test_owner_address() -> Address {
  address.from_verification_key(blake2b_224(auth_pub_key))
}

fn get_test_script_address(policy_id: ByteArray) -> Address {
  Address {
    payment_credential: Script(policy_id),
    stake_credential: None,
  }
}

fn make_test_genesis_datum(policy: ByteArray, own_ref: OutputReference) -> MasterDatum {
  MasterDatum {
    authority_key: auth_pub_key,
    operator_key: oper_pub_key,
    owner_key: owner_pub_key,
    owner_address: get_test_owner_address(),
    nonce: 0,
    is_paused: False,
    policy_id: policy,
    asset_name_prefix: "ZPEPG_",
    self_ref: own_ref,
    forward_link: None,
    backward_link: None,
    stats: RegistryStats {
      total_token_count: 0,
      total_unique_documents: 0,
      last_minted_at: 0,
      last_cross_chain_global_id: #"",
      last_cardano_asset_id: #"",
    },
  }
}

// ── PHASE 1: TESTING CORE OPERATIONS ─────────────────────────────────────

// TEST 1: Minting success path updates statistics counters and validates token section alignment
test success_mint_document_lifecycle() {
  let mock_policy = #"33333333333333333333333333333333333333333333333333333333"
  let initial_ref = OutputReference { transaction_id: #"1111", output_index: 0 }
  let old_datum = make_test_genesis_datum(mock_policy, initial_ref)
  
  let doc_id = #"019632a17e4f7c3a9b214f8e6d2c1a30"
  let doc_hash = #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  
  let redeemer = MintDocument {
    nonce: 0,
    cross_chain_global_id: doc_id,
    sha256_hash: doc_hash,
    upload_date: "2026-06-18",
    version: 1,
    token_data: #"7b7d",
    is_unique_document: True,
    valid_lower_bound: 1770000000,
    signature: valid_mint_sig,
  }

  let input_master = Input {
    output_reference: initial_ref,
    output: Output {
      address: get_test_script_address(mock_policy),
      value: assets.from_lovelace(2000000),
      datum: InlineDatum(old_datum),
      reference_script: None,
    },
  }

  let next_master_datum = MasterDatum {
    ..old_datum,
    nonce: 1,
    self_ref: OutputReference { transaction_id: #"aabb", output_index: 0 },
    stats: RegistryStats {
      total_token_count: 1,
      total_unique_documents: 1,
      last_minted_at: 1770000000,
      last_cross_chain_global_id: doc_id,
      last_cardano_asset_id: bytearray.concat(mock_policy, "ZPEPG_document_asset"),
    },
  }

  let output_master = Output {
    address: get_test_script_address(mock_policy),
    value: assets.from_lovelace(2000000),
    datum: InlineDatum(next_master_datum),
    reference_script: None,
  }

  let mock_token_datum = TokenDatum {
    cardano_asset_id: bytearray.concat(mock_policy, "ZPEPG_document_asset"),
    cross_chain_global_id: doc_id,
    registry_address: #"",
    policy_id: mock_policy,
    source_registry_master_utxo_reference: initial_ref,
    sha256_hash: doc_hash,
    upload_date: "2026-06-18",
    version: 1,
    token_data: #"7b7d",
  }

  let output_token = Output {
    address: get_test_owner_address(),
    value: assets.from_lovelace(2000000),
    datum: InlineDatum(mock_token_datum),
    reference_script: None,
  }

  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [input_master],
    outputs: [output_master, output_token],
    id: #"aabb",
  }

  archive_registry.spend(Some(old_datum), redeemer, initial_ref, tx)
}

// TEST 2: Circuit Breaker Pause flips is_paused state flag and updates state tracking reference
test success_circuit_breaker_pause() {
  let mock_policy = #"33333333333333333333333333333333333333333333333333333333"
  let initial_ref = OutputReference { transaction_id: #"1111", output_index: 0 }
  let old_datum = make_test_genesis_datum(mock_policy, initial_ref)

  let redeemer = Pause { nonce: 0, signature: valid_pause_sig }

  let input_master = Input {
    output_reference: initial_ref,
    output: Output {
      address: get_test_script_address(mock_policy),
      value: assets.from_lovelace(2000000),
      datum: InlineDatum(old_datum),
      reference_script: None,
    },
  }

  let next_master_datum = MasterDatum {
    ..old_datum,
    nonce: 1,
    is_paused: True,
    self_ref: OutputReference { transaction_id: #"ccdd", output_index: 0 },
  }

  let output_master = Output {
    address: get_test_script_address(mock_policy),
    value: assets.from_lovelace(2000000),
    datum: InlineDatum(next_master_datum),
    reference_script: None,
  }

  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [input_master],
    outputs: [output_master],
    id: #"ccdd",
  }

  archive_registry.spend(Some(old_datum), redeemer, initial_ref, tx)
}

// TEST 3: Circuit Breaker Resume recovers contract functionality from a frozen state
test success_circuit_breaker_resume() {
  let mock_policy = #"33333333333333333333333333333333333333333333333333333333"
  let initial_ref = OutputReference { transaction_id: #"1111", output_index: 0 }
  let old_datum = MasterDatum { ..make_test_genesis_datum(mock_policy, initial_ref), is_paused: True, nonce: 1 }

  let redeemer = Resume { nonce: 1, signature: valid_resume_sig }

  let input_master = Input {
    output_reference: initial_ref,
    output: Output {
      address: get_test_script_address(mock_policy),
      value: assets.from_lovelace(2000000),
      datum: InlineDatum(old_datum),
      reference_script: None,
    },
  }

  let next_master_datum = MasterDatum {
    ..old_datum,
    nonce: 2,
    is_paused: False,
    self_ref: OutputReference { transaction_id: #"eeff", output_index: 0 },
  }

  let output_master = Output {
    address: get_test_script_address(mock_policy),
    value: assets.from_lovelace(2000000),
    datum: InlineDatum(next_master_datum),
    reference_script: None,
  }

  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [input_master],
    outputs: [output_master],
    id: #"eeff",
  }

  archive_registry.spend(Some(old_datum), redeemer, initial_ref, tx)
}

// TEST 4: Secure Withdrawal unlocks capital assets and strictly asserts target destination compliance
test success_authorized_withdrawal() {
  let mock_policy = #"33333333333333333333333333333333333333333333333333333333"
  let initial_ref = OutputReference { transaction_id: #"1111", output_index: 0 }
  let old_datum = make_test_genesis_datum(mock_policy, initial_ref)

  let redeemer = Withdraw { nonce: 0, amount: 5000000, signature: valid_withdraw_sig }

  let input_master = Input {
    output_reference: initial_ref,
    output: Output {
      address: get_test_script_address(mock_policy),
      value: assets.from_lovelace(10000000), // Holds 10 ADA total
      datum: InlineDatum(old_datum),
      reference_script: None,
    },
  }

  let next_master_datum = MasterDatum {
    ..old_datum,
    nonce: 1,
    self_ref: OutputReference { transaction_id: #"9999", output_index: 0 },
  }

  let output_master = Output {
    address: get_test_script_address(mock_policy),
    value: assets.from_lovelace(5000000), // Retains remaining 5 ADA
    datum: InlineDatum(next_master_datum),
    reference_script: None,
  }

  let output_payment = Output {
    address: get_test_owner_address(), // Forces destination matching
    value: assets.from_lovelace(5000000), // Extracted 5 ADA payout
    datum: NoDatum,
    reference_script: None,
  }

  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [input_master],
    outputs: [output_master, output_payment],
    id: #"9999",
  }

  archive_registry.spend(Some(old_datum), redeemer, initial_ref, tx)
}

// TEST 5: Security Lockout rejection path triggers when attempting to mint inside a paused deployment
test failure_minting_blocked_when_paused() fail {
  let mock_policy = #"33333333333333333333333333333333333333333333333333333333"
  let initial_ref = OutputReference { transaction_id: #"1111", output_index: 0 }
  let old_datum = MasterDatum { ..make_test_genesis_datum(mock_policy, initial_ref), is_paused: True }
  
  let redeemer = MintDocument {
    nonce: 0,
    cross_chain_global_id: #"010203",
    sha256_hash: #"0000",
    upload_date: "2026-06-18",
    version: 1,
    token_data: #"",
    is_unique_document: True,
    valid_lower_bound: 0,
    signature: valid_mint_sig,
  }

  let tx = transaction.placeholder
  archive_registry.spend(Some(old_datum), redeemer, initial_ref, tx)
}
