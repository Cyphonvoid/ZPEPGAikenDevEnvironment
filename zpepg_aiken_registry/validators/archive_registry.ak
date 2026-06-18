use aiken/primitive/bytearray
use aiken/crypto.{VerificationKey, Signature, verify_ed25519_signature}
use cardano/address.{Address, Script}
use cardano/transaction.{
  OutputReference, Transaction, TransactionId, Input, Output, InlineDatum,
}
use aiken/collection/list
use registry_contract_types.{
  MasterDatum,
  RegistryAction,
  TokenDatum,
  RegistryStats,
  CreateTokenAction,
  KeyType,
  verify_canonical_master,
  find_master_input,
  find_master_output_with_index,
  find_token_output_with_datum,
  datum_from_output,
  make_output_ref,
}

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
