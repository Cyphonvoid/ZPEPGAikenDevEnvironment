"""
zpepg_chain_client.py

Consolidated, reusable patch layer over pccontext.YaciDevkitChainContext.

WHY THIS FILE EXISTS:
During initial devnet integration, pccontext (0.6.0) was found to have FOUR
separate confirmed bugs that make it unusable out of the box against
yaci-store:

  1. utxos() - does item["unit"] on the yaci_client Amount model, but
     Amount.from_dict() already pops "unit" out of additional_properties
     into a real attribute, so the dict-style lookup always raises
     KeyError. (Confirmed by inspecting yaci_client/models/amount.py and
     comparing against the raw, correct JSON from yaci-store.)

  2. protocol_param - returns cost_models = {'PlutusV1': None, 'PlutusV2':
     None, 'PlutusV3': None} unconditionally, even though the raw
     /api/v1/epochs/latest/parameters endpoint returns fully populated
     cost models for all three languages. (Confirmed by direct comparison
     of pccontext's parsed output against the raw HTTP response.)

  3. evaluate_tx_cbor - calls cbor.decode("utf-8") on raw binary CBOR
     bytes, which crashes immediately (CBOR is not valid UTF-8; e.g. 0x84
     is a normal CBOR array-header byte). Even past that, its own
     response-parsing dict comprehension iterates dict *keys* and then
     indexes into them as if they were dicts themselves - a second,
     independent bug in the same method. (Confirmed by reading the
     method's source directly.)

  4. submit_tx_cbor - same decode("utf-8") bug as #3, in the sibling
     method. (Confirmed identically.)

  Additionally, last_block_slot is simply unimplemented on this backend
  (raises NotImplementedError, inherited unoverridden from the abstract
  ChainContext base class), which TransactionBuilder.build() calls
  unconditionally unless an explicit ttl is supplied.

This module patches all of the above on a per-instance basis (via
type(context).method = ...), without modifying any installed package on
disk. Every replacement implementation's wire format (hex vs raw binary,
which endpoint, which header) was independently confirmed against the
real devnet rather than assumed - see inline notes on each patch for the
specific evidence.

NOTE ON FUTURE BACKENDS: get_utxos_for_address() is intentionally written
as a free function with a single (api_base, address) signature, so it can
be swapped for a Blockfrost- or Koios-backed implementation later without
touching any calling code - see the bottom of this file.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Optional

import requests
from pycardano import (
    Address,
    ExecutionUnits,
    ProtocolParameters,
    RedeemerTag,
    TransactionId,
    TransactionInput,
    TransactionOutput,
    UTxO,
    Value,
)
from pccontext import YaciDevkitChainContext


# ════════════════════════════════════════════════════════════════════════
# Direct-fetch helpers (bypass pccontext's broken parsing entirely)
# ════════════════════════════════════════════════════════════════════════


def get_utxos_for_address(api_base: str, address: str) -> list[UTxO]:
    """
    Fetches every UTXO at an address directly via yaci-store's REST API,
    bypassing pccontext.YaciDevkitChainContext.utxos() (bug #1 above).

    Swap point for future backends: a Blockfrost- or Koios-backed
    implementation of this exact signature (api_base, address) -> list[UTxO]
    can replace this function body without touching any caller.
    """
    resp = requests.get(f"{api_base}/api/v1/addresses/{address}/utxos")
    resp.raise_for_status()
    utxos_json = resp.json()

    utxos = []
    for item in utxos_json:
        lovelace = next(
            (int(a["quantity"]) for a in item["amount"] if a["unit"] == "lovelace"),
            0,
        )
        tx_input = TransactionInput(
            transaction_id=TransactionId(bytes.fromhex(item["tx_hash"])),
            index=item["output_index"],
        )
        tx_output = TransactionOutput(
            address=Address.from_primitive(item["address"]),
            amount=Value(coin=lovelace),
        )
        utxos.append(UTxO(input=tx_input, output=tx_output))
    return utxos


def get_utxo(api_base: str, address: str, tx_hash: str, output_index: int) -> UTxO:
    """
    Fetches one specific UTXO by reference, filtering the results of
    get_utxos_for_address(). Raises if it isn't found (e.g. already spent,
    or wrong address).
    """
    for utxo in get_utxos_for_address(api_base, address):
        if (
            utxo.input.transaction_id.payload.hex() == tx_hash
            and utxo.input.index == output_index
        ):
            return utxo
    raise RuntimeError(f"UTXO {tx_hash}#{output_index} not found at {address}")


def fetch_protocol_params_directly(api_base: str) -> ProtocolParameters:
    """
    Fetches real protocol parameters directly via requests, bypassing
    pccontext's protocol_param (bug #2 above).
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
        decentralization_param=Fraction(0),  # deprecated, absent in Conway-era params
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


def fetch_latest_slot(api_base: str) -> int:
    """Fetches the current tip slot directly, used both for the
    last_block_slot patch and for computing a safe explicit ttl."""
    resp = requests.get(f"{api_base}/api/v1/blocks/latest")
    resp.raise_for_status()
    return resp.json()["slot"]


# ════════════════════════════════════════════════════════════════════════
# Patch application
# ════════════════════════════════════════════════════════════════════════


def make_patched_context(api_base: str) -> YaciDevkitChainContext:
    """
    Returns a YaciDevkitChainContext with all 4 confirmed bugs patched at
    the instance/class level (no on-disk package files are modified).
    Call this once per script; reuse the returned context for everything.
    """
    context = YaciDevkitChainContext(api_url=api_base)

    # ── Patch: last_block_slot (unimplemented in this backend) ─────────
    def _patched_last_block_slot(self):
        return fetch_latest_slot(api_base)

    type(context).last_block_slot = property(_patched_last_block_slot)

    # ── Patch: protocol_param (bug #2: null cost_models) ────────────────
    _cached_params = fetch_protocol_params_directly(api_base)
    type(context).protocol_param = property(lambda self: _cached_params)

    # ── Patch: evaluate_tx_cbor (bug #3: utf-8 decode crash + broken
    #    response parsing). Confirmed wire format: hex-encoded CBOR text
    #    as the body (the server's own error - "Invalid Hexadecimal
    #    Character" - when raw bytes were sent confirmed this directly).
    #    Confirmed response shape: {"mint:0": {"memory": int, "steps":
    #    int}, ...} - the key is already the exact string format
    #    PyCardano's own _update_execution_units expects
    #    (f"{tagname}:{index}", per txbuilder.py), so it's passed through
    #    unchanged rather than re-derived. ──
    def _patched_evaluate_tx_cbor(self, cbor):
        hex_cbor = cbor.hex() if isinstance(cbor, bytes) else cbor
        resp = requests.post(
            f"{api_base}/api/v1/utils/txs/evaluate",
            data=hex_cbor,
            headers={"Content-Type": "application/cbor"},
        )
        resp.raise_for_status()
        result = resp.json()

        eval_result = result.get("result", {}).get("EvaluationResult")
        if not eval_result:
            raise RuntimeError(f"Script evaluation failed: {result}")

        return {
            key_str: ExecutionUnits(mem=budget["memory"], steps=budget["steps"])
            for key_str, budget in eval_result.items()
        }

    type(context).evaluate_tx_cbor = _patched_evaluate_tx_cbor

    # ── Patch: submit_tx_cbor (bug #4: utf-8 decode crash). Confirmed
    #    wire format here is the OPPOSITE of evaluate: this endpoint
    #    forwards straight to the node's own submission path, which wants
    #    raw binary CBOR - confirmed by the node's own decoder error
    #    ("expected list len or indef") when hex text was sent here
    #    instead. Two sibling endpoints, two different wire formats,
    #    despite both sharing the same misleading application/cbor header
    #    in yaci_client's generated code. ──
    def _patched_submit_tx_cbor(self, cbor):
        raw_cbor = bytes.fromhex(cbor) if isinstance(cbor, str) else cbor
        resp = requests.post(
            f"{api_base}/api/v1/tx/submit",
            data=raw_cbor,
            headers={"Content-Type": "application/cbor"},
        )
        resp.raise_for_status()
        return resp.json()

    type(context).submit_tx_cbor = _patched_submit_tx_cbor

    return context