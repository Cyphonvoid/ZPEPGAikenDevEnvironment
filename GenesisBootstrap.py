"""
ZPEPG Genesis Bootstrap Transaction.

This is a ONE-TIME script. It:
  1. Spends the genesis UTXO (consumed exactly once, ever, by beacon_policy's
     one-shot minting check).
  2. Mints exactly 1 beacon token under beacon_policy.
  3. Creates the very first archive_registry master UTXO, carrying the
     beacon and a fully-initialized MasterDatum (nonce=0, your three admin
     keys, zeroed RegistryStats, no chain links yet).

Run this exactly once per deployment. Running it again will fail at the
beacon_policy mint check, since the genesis UTXO will already be spent.

PREREQUISITES (all already confirmed working in this project):
  - Devnet running (yaci-devkit up --enable-yaci-store --interactive,
    create-node -o --start)
  - genesis_ref confirmed unspent at Address #18
  - beacon_policy compiled + parameterized with genesis_ref (plutus.json
    already has the applied policy)
  - registry_contract compiled (plutus.json)
"""

import json
from jaraco import context
import requests
from pycardano import (
    Address,
    Network,
    TransactionBuilder,
    TransactionOutput,
    Value,
    MultiAsset,
    ScriptHash,
    AssetName,
    Asset,
    PlutusV3Script,
    Redeemer,
    HDWallet,
    PaymentExtendedSigningKey,
    StakeExtendedSigningKey,
    TransactionInput,
    TransactionId,
    UTxO,
)
from pccontext import YaciDevkitChainContext

from zpepg_types import (
    OutputReference,
    MasterDatum,
    RegistryStats,
    PlutusAddress,
    VerificationKeyCredential,
    InlineStakeCredential,
    SomeStakeCredential,
    NoneChainLink,
    AikenFalse,
    MintBeacon,
)

# ════════════════════════════════════════════════════════════════════════
# CONFIG - all values confirmed earlier in this project
# ════════════════════════════════════════════════════════════════════════

MNEMONIC = "test test test test test test test test test test test test test test test test test test test test test test test sauce"
WALLET_ACCOUNT_INDEX = 18  # Address #18, holds the genesis UTXO

GENESIS_TX_HASH = "c7565416e7553cdf8fdac8bf054b4b3de19d06b72efd00c47823335d7156ed1f"
GENESIS_OUTPUT_INDEX = 0

BEACON_ASSET_NAME = b"ZPEPG-BEACON-TEST"
REGISTRY_ASSET_NAME_PREFIX = b"ZPEPG-ARCHIVE-DOC"  # adjust if you'd chosen something else

AUTHORITY_KEY_HEX = "aa3edc38bd2386f9a6bdd3bf633dea7e2045c85476a8d445f0c3fc35ffa42f6a"
OPERATOR_KEY_HEX = "fa2051685c04478e1d351194e3303727c087a6498d6cf4f3050d37ba76f0edc8"
OWNER_KEY_HEX = "186855b264674f7aa1e9a8c3155493384486e0cead1c5c3453551e0f0afc6b49"

PLUTUS_JSON_PATH = "zpepg_aiken_registry/plutus.json"
YACI_STORE_URL = "http://localhost:8080"

from fractions import Fraction
from pycardano import ProtocolParameters


def fetch_protocol_params_directly(api_base: str) -> ProtocolParameters:
    """
    Fetches real protocol parameters directly via requests against
    yaci-store's REST API, bypassing pccontext.YaciDevkitChainContext
    .protocol_param, which returns cost_models = {'PlutusV1': None,
    'PlutusV2': None, 'PlutusV3': None} - confirmed empty/null even
    though the raw /api/v1/epochs/latest/parameters endpoint returns
    fully populated cost models for all three languages. This is a
    second confirmed pccontext bug in this version (separate from the
    UTXO 'unit' KeyError bug), so we sidestep it the same way.
    """
    resp = requests.get(f"{api_base}/api/v1/epochs/latest/parameters")
    resp.raise_for_status()
    p = resp.json()

    return ProtocolParameters(
        min_fee_constant=p["min_fee_b"],
        min_fee_coefficient=p["min_fee_a"],
        max_block_size=p["max_block_size"],
        max_tx_size=p["max_tx_size"],
        max_block_header_size=p["max_block_header_size"],
        key_deposit=int(p["key_deposit"]),
        pool_deposit=int(p["pool_deposit"]),
        pool_influence=Fraction(p["a0"]),
        monetary_expansion=Fraction(p["rho"]),
        treasury_expansion=Fraction(p["tau"]),
        decentralization_param=Fraction(0),  # not present in Conway-era params; deprecated field
        extra_entropy="",
        protocol_major_version=p["protocol_major_ver"],
        protocol_minor_version=p["protocol_minor_ver"],
        min_utxo=int(p.get("coins_per_utxo_size", 0)),
        min_pool_cost=int(p["min_pool_cost"]),
        price_mem=Fraction(p["price_mem"]),
        price_step=Fraction(p["price_step"]),
        max_tx_ex_mem=int(p["max_tx_ex_mem"]),
        max_tx_ex_steps=int(p["max_tx_ex_steps"]),
        max_block_ex_mem=int(p["max_block_ex_mem"]),
        max_block_ex_steps=int(p["max_block_ex_steps"]),
        max_val_size=int(p["max_val_size"]),
        collateral_percent=p["collateral_percent"],
        max_collateral_inputs=p["max_collateral_inputs"],
        coins_per_utxo_word=int(p.get("coins_per_utxo_size", 0)),
        coins_per_utxo_byte=int(p.get("coins_per_utxo_size", 0)),
        cost_models=p["cost_models"],
        maximum_reference_scripts_size=None,
        min_fee_reference_scripts=None,
    )


def fetch_evaluate_tx_directly(api_base: str, tx_cbor: bytes) -> dict:
    """
    Calls yaci-store's /api/v1/utils/txs/evaluate. Despite yaci_client's
    generated code sending Content-Type: application/cbor with raw binary
    content, the server actually expects the body to be the CBOR encoded
    as a hex string - confirmed directly from the server's own error:
    "Invalid Hexadecimal Character" when raw bytes were sent.
    """
    hex_cbor = tx_cbor.hex()
    resp = requests.post(
        f"{api_base}/api/v1/utils/txs/evaluate",
        data=hex_cbor,
        headers={"Content-Type": "application/cbor"},
    )
    if resp.status_code >= 400:
        print("ERROR RESPONSE BODY:", resp.text)
    resp.raise_for_status()
    return resp.json()


def load_validator(blueprint: dict, title: str) -> dict:
    for v in blueprint["validators"]:
        if v["title"] == title:
            return v
    raise ValueError(f"Validator '{title}' not found in blueprint")


def fetch_utxo_directly(api_base: str, address: str, tx_hash: str, output_index: int) -> UTxO:
    """
    Fetches a specific UTXO directly via requests against yaci-store's REST
    API, bypassing pccontext.YaciDevkitChainContext.utxos() which has a
    confirmed bug in this version (0.6.0): it does `item["unit"]` on the
    yaci_client Amount model, but Amount.from_dict() already pops "unit"
    out of additional_properties into a proper attribute - so the dict-style
    lookup always raises KeyError. This is a real upstream bug in pccontext,
    not a problem with our data (the raw JSON from yaci-store correctly
    contains "unit").
    """
    resp = requests.get(f"{api_base}/api/v1/addresses/{address}/utxos")
    resp.raise_for_status()
    utxos_json = resp.json()

    for item in utxos_json:
        if item["tx_hash"] == tx_hash and item["output_index"] == output_index:
            lovelace = next(
                (int(a["quantity"]) for a in item["amount"] if a["unit"] == "lovelace"),
                0,
            )
            tx_input = TransactionInput(
                transaction_id=TransactionId(bytes.fromhex(tx_hash)),
                index=output_index,
            )
            tx_output = TransactionOutput(
                address=Address.from_primitive(item["address"]),
                amount=Value(coin=lovelace),
            )
            return UTxO(input=tx_input, output=tx_output)

    raise RuntimeError(f"UTXO {tx_hash}#{output_index} not found at {address}")


def main():
    # ── 1. Chain context ───────────────────────────────────────────────
    context = YaciDevkitChainContext(api_url=YACI_STORE_URL)

    # pccontext's YaciDevkitChainContext does not implement last_block_slot
    # (confirmed: raises NotImplementedError, inherited unoverridden from
    # the abstract ChainContext base class). Unlike ttl, which we can pass
    # explicitly, TransactionBuilder.build() calls context.last_block_slot
    # unconditionally - so we patch it directly onto this instance, backed
    # by the same /api/v1/blocks/latest endpoint already confirmed working.
    def _patched_last_block_slot(self):
        resp = requests.get(f"{YACI_STORE_URL}/api/v1/blocks/latest")
        resp.raise_for_status()
        return resp.json()["slot"]

    type(context).last_block_slot = property(_patched_last_block_slot)
    _cached_params = fetch_protocol_params_directly(YACI_STORE_URL)
    type(context).protocol_param = property(lambda self: _cached_params)
    
    def _patched_evaluate_tx_cbor(self, cbor):
        """
        Replaces pccontext's broken evaluate_tx_cbor (confirmed broken: it
        decodes raw binary CBOR as utf-8, which crashes immediately, and its
        response parsing also doesn't work). Sends hex-encoded CBOR text as
        the body (confirmed correct wire format from the server's own error
        when raw bytes were sent). Response shape confirmed directly by
        inspection: {"mint:0": {"memory": int, "steps": int}, ...} - the key
        is already the exact string format PyCardano's own
        _update_execution_units expects (f"{tagname}:{index}"), so we pass
        it through unchanged rather than re-deriving it.
        """
        hex_cbor = cbor.hex() if isinstance(cbor, bytes) else cbor
        resp = requests.post(
            f"{YACI_STORE_URL}/api/v1/utils/txs/evaluate",
            data=hex_cbor,
            headers={"Content-Type": "application/cbor"},
        )
        resp.raise_for_status()
        result = resp.json()

        eval_result = result.get("result", {}).get("EvaluationResult")
        if not eval_result:
            raise RuntimeError(f"Script evaluation failed: {result}")

        from pycardano import ExecutionUnits
        return {
            key_str: ExecutionUnits(mem=budget["memory"], steps=budget["steps"])
            for key_str, budget in eval_result.items()
        }

    type(context).evaluate_tx_cbor = _patched_evaluate_tx_cbor


    def _patched_submit_tx_cbor(self, cbor):
        """
        Submit endpoint forwards directly to the node's tx submission path,
        which expects raw binary CBOR - confirmed by the node's own decoder
        error ("expected list len or indef") when hex text was sent instead.
        This differs from /api/v1/utils/txs/evaluate, which goes through
        Ogmios's layer and does want hex text - two different downstream
        consumers, two different wire formats, despite both endpoints sharing
        the same misleading application/cbor header in yaci_client's generated
        code.
        """
        raw_cbor = bytes.fromhex(cbor) if isinstance(cbor, str) else cbor
        resp = requests.post(
            f"{YACI_STORE_URL}/api/v1/tx/submit",
            data=raw_cbor,
            headers={"Content-Type": "application/cbor"},
        )
        if resp.status_code >= 400:
            print("SUBMIT ERROR RESPONSE BODY:", resp.text)
        resp.raise_for_status()
        return resp.json()


    type(context).submit_tx_cbor = _patched_submit_tx_cbor
    # ── 2. Derive Address #18's signing keys from mnemonic (VERIFIED
    #      working earlier: Match: True against the real Yaci address) ──
    hdwallet = HDWallet.from_mnemonic(MNEMONIC)

    payment_hdwallet = hdwallet.derive_from_path(f"m/1852'/1815'/{WALLET_ACCOUNT_INDEX}'/0/0")
    payment_esk = PaymentExtendedSigningKey.from_hdwallet(payment_hdwallet)
    payment_evk = payment_esk.to_verification_key()

    staking_hdwallet = hdwallet.derive_from_path(f"m/1852'/1815'/{WALLET_ACCOUNT_INDEX}'/2/0")
    staking_esk = StakeExtendedSigningKey.from_hdwallet(staking_hdwallet)
    staking_evk = staking_esk.to_verification_key()

    funding_address = Address(
        payment_part=payment_evk.hash(),
        staking_part=staking_evk.hash(),
        network=Network.TESTNET,
    )
    print(f"Funding/signing address: {funding_address}")

    # ── 3. Load both compiled scripts from the blueprint ───────────────
    with open(PLUTUS_JSON_PATH) as f:
        blueprint = json.load(f)

    beacon_validator = load_validator(blueprint, "beacon_contract.beacon_policy.mint")
    registry_validator = load_validator(blueprint, "registry_contract.archive_registry.spend")

    beacon_script = PlutusV3Script(bytes.fromhex(beacon_validator["compiledCode"]))
    beacon_policy_id = ScriptHash(bytes.fromhex(beacon_validator["hash"]))

    registry_script = PlutusV3Script(bytes.fromhex(registry_validator["compiledCode"]))
    registry_policy_id = ScriptHash(bytes.fromhex(registry_validator["hash"]))
    registry_script_address = Address(payment_part=registry_policy_id, network=Network.TESTNET)

    print(f"Beacon policy ID:   {beacon_policy_id}")
    print(f"Registry policy ID: {registry_policy_id}")
    print(f"Registry script address: {registry_script_address}")

    # ── 4. Confirm genesis UTXO is still there - fetched directly via
    #      requests, bypassing pccontext's buggy utxos() (see
    #      fetch_utxo_directly's docstring for the confirmed root cause) ──
    genesis_ref_input = fetch_utxo_directly(
        YACI_STORE_URL, str(funding_address), GENESIS_TX_HASH, GENESIS_OUTPUT_INDEX
    )
    print(f"Genesis UTXO confirmed: {genesis_ref_input.input}")

    # ── 5. Build the beacon mint redeemer ───────────────────────────────
    beacon_redeemer = Redeemer(MintBeacon())

    # ── 6. Build owner_address as a Plutus-level Address ────────────────
    owner_plutus_address = PlutusAddress(
        payment_credential=VerificationKeyCredential(bytes(payment_evk.hash())),
        stake_credential=SomeStakeCredential(
            InlineStakeCredential(VerificationKeyCredential(bytes(staking_evk.hash())))
        ),
    )

    # ── 7. Build the genesis MasterDatum (nonce=0, everything zeroed) ──
    genesis_master_datum = MasterDatum(
        authority_key=bytes.fromhex(AUTHORITY_KEY_HEX),
        operator_key=bytes.fromhex(OPERATOR_KEY_HEX),
        owner_key=bytes.fromhex(OWNER_KEY_HEX),
        owner_address=owner_plutus_address,
        nonce=0,
        is_paused=AikenFalse(),
        policy_id=bytes(registry_policy_id),
        asset_name_prefix=REGISTRY_ASSET_NAME_PREFIX,
        beacon_policy_id=bytes(beacon_policy_id),
        beacon_asset_name=BEACON_ASSET_NAME,
        forward_link=NoneChainLink(),
        backward_link=NoneChainLink(),
        stats=RegistryStats(
            total_token_count=0,
            total_unique_documents=0,
            last_minted_at=0,
            last_cross_chain_global_id=b"",
            last_cardano_asset_id=b"",
        ),
    )

    # ── 8. Build the transaction ────────────────────────────────────────
    # NOTE: pccontext's YaciDevkitChainContext does not implement
    # last_block_slot (confirmed: raises NotImplementedError from the
    # ChainContext base class - it's an abstract property never overridden
    # in this backend). TransactionBuilder.build() calls this automatically
    # to compute a default TTL unless ttl is supplied explicitly. So we
    # fetch the current tip slot ourselves via direct API call and pass
    # ttl explicitly, sidestepping the missing property entirely.
    tip_resp = requests.get(f"{YACI_STORE_URL}/api/v1/blocks/latest")
    tip_resp.raise_for_status()
    current_slot = tip_resp.json()["slot"]
    ttl_buffer_slots = 200  # generous buffer; devnet blocks are ~1s each
    print(f"Current tip slot: {current_slot}, setting ttl={current_slot + ttl_buffer_slots}")

    builder = TransactionBuilder(context, ttl=current_slot + ttl_buffer_slots)
    builder.add_input(genesis_ref_input)
    builder.add_minting_script(beacon_script, beacon_redeemer)

    beacon_multi_asset = MultiAsset(
        {beacon_policy_id: Asset({AssetName(BEACON_ASSET_NAME): 1})}
    )
    builder.mint = beacon_multi_asset

    # Master UTXO output: registry script address, holding the beacon +
    # enough ADA for min-UTXO with this datum size, datum = genesis MasterDatum
    master_output = TransactionOutput(
        address=registry_script_address,
        amount=Value(coin=3_000_000, multi_asset=beacon_multi_asset),
        datum=genesis_master_datum,
    )
    builder.add_output(master_output)

    # ── 9. Sign and submit ──────────────────────────────────────────────
    signed_tx = builder.build_and_sign(
        signing_keys=[payment_esk],
        change_address=funding_address,
    )

    print()
    print("Submitting genesis bootstrap transaction...")
    context.submit_tx(signed_tx)

    print()
    print(f"SUCCESS. Genesis bootstrap tx ID: {signed_tx.id}")
    print(f"Master UTXO: {signed_tx.id}#0  (verify index matches actual output position)")
    print()
    print("Save these values - they're permanent for this deployment:")
    print(f"  beacon_policy_id  = {beacon_policy_id}")
    print(f"  beacon_asset_name = {BEACON_ASSET_NAME.decode()}")
    print(f"  registry_policy_id = {registry_policy_id}")
    print(f"  registry_script_address = {registry_script_address}")


if __name__ == "__main__":
    main()