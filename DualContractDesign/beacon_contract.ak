// =============================================================================
// VALIDATOR: beacon_policy
// PURPOSE: One-shot minting policy for the ZPEPG Master Registry beacon token.
//
// WHY THIS EXISTS:
// The archive_registry script address can receive arbitrary payments from
// anyone — Cardano addresses accept payments unconditionally, script or not.
// That means a decoy UTXO with a hand-crafted, structurally valid-looking
// MasterDatum can sit at the same script address as the real master UTXO,
// without ever touching archive_registry's spend or mint logic (plain
// payments never invoke either). A field inside a datum — no matter how
// carefully checked — can always be copied verbatim into a decoy, because
// datum fields are just data.
//
// The beacon token solves discovery, not mutation safety (mutation safety
// was already solved by the authority/operator/owner signature checks in
// archive_registry). It gives any reader — your own driver, a third-party
// indexer, a future integration with no prior context — a ledger-enforced,
// non-copyable fact: "the real master UTXO is whichever UTXO holds 1 unit
// of THIS exact token." Unlike a datum field, a native asset unit cannot be
// duplicated; eUTXO guarantees it lives in exactly one place at a time.
//
// ONE-SHOT GUARANTEE:
// This policy is parameterized by a specific genesis OutputReference, fixed
// at compile/instantiation time. Minting under this policy is only allowed
// if that exact OutputReference is being spent as an input in the same
// transaction. Since any OutputReference can be spent at most once ever,
// this policy can fire successfully at most once, ever, for any party,
// permanently — there is no admin switch, no flag, no key that could allow
// a second mint. The guarantee comes from eUTXO's no-double-spend rule
// itself, not from anything this script actively checks at runtime beyond
// "is that input present."
//
// USAGE:
// Deploy this policy instantiated with the OutputReference of whichever
// UTXO you intend to consume as the genesis input of your first
// archive_registry master UTXO transaction. Mint exactly 1 unit of the
// beacon asset in that same transaction, and send it to the
// archive_registry script address alongside the very first MasterDatum.
// From that point forward, archive_registry's spend validator requires the
// beacon to be carried forward into every successor master UTXO — see
// archive_registry.ak.
// =============================================================================

use aiken/collection/dict
use aiken/collection/list
use cardano/assets
use cardano/transaction.{OutputReference, Transaction}

// ── Mint Redeemer ─────────────────────────────────────────────────────────
// A single action. No burn, no re-mint path — the beacon is permanent,
// non-burnable, by design, for the same reason document tokens are
// non-burnable in archive_registry: it must remain a stable, permanent
// marker of the canonical master UTXO for as long as the registry exists.

pub type BeaconAction {
  MintBeacon
}

// ── Beacon Policy ────────────────────────────────────────────────────────
// Parameterized by genesis_ref: the exact OutputReference that must be
// spent as an input for this policy to ever succeed. Bake this in at
// instantiation time (e.g. via aiken blueprint apply-params, or your
// off-chain library's policy-application step) before deployment.

validator beacon_policy(genesis_ref: OutputReference) {
  mint(redeemer: BeaconAction, policy_id: ByteArray, self: Transaction) {
    when redeemer is {
      MintBeacon -> {
        // 1. The genesis OutputReference this policy is parameterized on
        //    must be present as an input in this transaction. Since an
        //    OutputReference can only ever be spent once, this is what
        //    makes the mint impossible to repeat — not a runtime flag,
        //    a structural fact about the eUTXO ledger.
        expect list.any(
          self.inputs,
          fn(input) { input.output_reference == genesis_ref },
        )

        // 2. Exactly one beacon unit must be minted under this policy,
        //    in this transaction. No more, no less.
        let minted_assets = assets.tokens(self.mint, policy_id)
        expect [Pair(_asset_name, quantity)] = dict.to_pairs(minted_assets)
        expect quantity == 1

        True
      }
    }
  }
}
