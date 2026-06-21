"""
ZPEPG Bootstrap - Chain data provider abstraction.

A small Protocol-based abstraction over "fetch UTXOs at an address" and
"submit/confirm a transaction", so the rest of the bootstrap script never
talks to Yaci Store / Blockfrost / any other backend directly. Swapping
providers later (Yaci Store now, Blockfrost later per the original spec)
means writing one new class that satisfies ChainProvider, not touching
any calling code.

The Yaci Store implementation here reproduces the EXACT workarounds
confirmed necessary in the manual bootstrap script (cardano_genesis.py):
  - protocol params: pccontext's YaciDevkitChainContext.protocol_param
    returns null cost_models; we hit /api/v1/epochs/latest/parameters
    directly instead.
  - tx evaluation: /api/v1/utils/txs/evaluate wants hex-encoded CBOR
    as the body text, NOT raw binary, despite the misleading
    Content-Type: application/cbor header.
  - tx submission: /api/v1/tx/submit wants RAW BINARY CBOR, the
    opposite convention from the evaluate endpoint - confirmed by the
    node's own decoder error when hex text was sent there instead.
  - UTXO fetching: pccontext's own utxos() has a confirmed KeyError
    bug (does item["unit"] on an object that already popped "unit"
    into a real attribute), so we hit /api/v1/addresses/{address}/utxos
    directly instead.
  - last_block_slot: pccontext's YaciDevkitChainContext does not
    implement this (raises NotImplementedError) but TransactionBuilder
    needs it for default TTL computation, so we fetch /api/v1/blocks/latest
    ourselves and pass ttl explicitly rather than relying on it.

These aren't stylistic choices - they're workarounds for specific,
confirmed bugs in pccontext as pinned in this project. Do not "simplify"
this back to using pccontext's own methods without re-confirming those
bugs are fixed in whatever pccontext version is installed.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Protocol

import requests
from pycardano import ExecutionUnits, ProtocolParameters


@dataclass(frozen=True)
class UtxoAsset:
    """A single native asset quantity within a UTXO."""
    unit: str  # "lovelace" or policy_id+asset_name hex, per the provider's convention
    quantity: int


@dataclass(frozen=True)
class UtxoInfo:
    """Provider-agnostic view of a single UTXO. Enough info for both the
    interactive picker display and building a TransactionInput/TransactionOutput."""
    tx_hash: str
    output_index: int
    address: str
    lovelace: int
    assets: tuple[UtxoAsset, ...]

    @property
    def ref_str(self) -> str:
        return f"{self.tx_hash}#{self.output_index}"

    def format_summary(self) -> str:
        asset_part = ""
        if self.assets:
            asset_part = f", {len(self.assets)} native asset(s)"
        ada = self.lovelace / 1_000_000
        return f"{self.ref_str}  ({ada:.6f} ADA{asset_part})"


class ProviderError(Exception):
    """Raised for any provider-level failure (network, bad response shape, etc.)."""


class ChainProvider(Protocol):
    """Everything the rest of bootstrap needs from a chain data backend.
    Implement this Protocol to add a new provider (e.g. Blockfrost)."""

    def get_utxos(self, address: str) -> list[UtxoInfo]:
        ...

    def find_utxo(self, address: str, tx_hash: str, output_index: int) -> UtxoInfo | None:
        ...

    def current_slot(self) -> int:
        ...

    def protocol_parameters(self) -> ProtocolParameters:
        ...

    def evaluate_tx(self, tx_cbor: bytes) -> dict[str, ExecutionUnits]:
        ...

    def submit_tx(self, tx_cbor: bytes) -> str:
        """Submit signed tx CBOR. Returns whatever identifier/response the
        backend gives back (provider-specific; callers should rely on the
        tx hash they already computed client-side, not parse this)."""
        ...


class YaciStoreProvider:
    """ChainProvider implementation against a local Yaci DevKit / Yaci Store
    instance, talked to directly via its REST API rather than through
    pccontext (see module docstring for why)."""

    def __init__(self, api_base_url: str):
        self.api_base_url = api_base_url.rstrip("/")

    def _get(self, path: str) -> dict | list:
        url = f"{self.api_base_url}{path}"
        try:
            resp = requests.get(url)
            resp.raise_for_status()
        except requests.RequestException as e:
            raise ProviderError(f"GET {url} failed: {e}") from e
        return resp.json()

    def get_utxos(self, address: str) -> list[UtxoInfo]:
        try:
            utxos_json = self._get(f"/api/v1/addresses/{address}/utxos")
        except ProviderError:
            raise

        if not isinstance(utxos_json, list):
            raise ProviderError(
                f"Unexpected response shape from /addresses/{{address}}/utxos: "
                f"expected a list, got {type(utxos_json).__name__}"
            )

        results: list[UtxoInfo] = []
        for item in utxos_json:
            lovelace = 0
            assets: list[UtxoAsset] = []
            for amount in item.get("amount", []):
                unit = amount["unit"]
                quantity = int(amount["quantity"])
                if unit == "lovelace":
                    lovelace = quantity
                else:
                    assets.append(UtxoAsset(unit=unit, quantity=quantity))

            results.append(
                UtxoInfo(
                    tx_hash=item["tx_hash"],
                    output_index=item["output_index"],
                    address=item.get("address", address),
                    lovelace=lovelace,
                    assets=tuple(assets),
                )
            )

        return results

    def find_utxo(self, address: str, tx_hash: str, output_index: int) -> UtxoInfo | None:
        for utxo in self.get_utxos(address):
            if utxo.tx_hash == tx_hash and utxo.output_index == output_index:
                return utxo
        return None

    def current_slot(self) -> int:
        data = self._get("/api/v1/blocks/latest")
        if "slot" not in data:
            raise ProviderError(f"/blocks/latest response missing 'slot' field: {data}")
        return data["slot"]

    def protocol_parameters(self) -> ProtocolParameters:
        p = self._get("/api/v1/epochs/latest/parameters")
        try:
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
                decentralization_param=Fraction(0),  # deprecated, not present in Conway era
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
        except KeyError as e:
            raise ProviderError(
                f"/epochs/latest/parameters response missing expected field: {e}"
            ) from e

    def evaluate_tx(self, tx_cbor: bytes) -> dict[str, ExecutionUnits]:
        # CONFIRMED wire format: hex-encoded CBOR as the body text, despite
        # the application/cbor header. Sending raw bytes here produces
        # "Invalid Hexadecimal Character" from the server.
        hex_cbor = tx_cbor.hex()
        url = f"{self.api_base_url}/api/v1/utils/txs/evaluate"
        try:
            resp = requests.post(url, data=hex_cbor, headers={"Content-Type": "application/cbor"})
        except requests.RequestException as e:
            raise ProviderError(f"POST {url} failed: {e}") from e

        if resp.status_code >= 400:
            raise ProviderError(f"Tx evaluation failed ({resp.status_code}): {resp.text}")

        result = resp.json()
        eval_result = result.get("result", {}).get("EvaluationResult")
        if not eval_result:
            raise ProviderError(f"Script evaluation failed: {result}")

        return {
            key_str: ExecutionUnits(mem=budget["memory"], steps=budget["steps"])
            for key_str, budget in eval_result.items()
        }

    def submit_tx(self, tx_cbor: bytes) -> str:
        # CONFIRMED wire format: RAW BINARY CBOR here, the opposite of
        # evaluate_tx above. Sending hex text here produces "expected list
        # len or indef" from the node's decoder.
        url = f"{self.api_base_url}/api/v1/tx/submit"
        try:
            resp = requests.post(url, data=tx_cbor, headers={"Content-Type": "application/cbor"})
        except requests.RequestException as e:
            raise ProviderError(f"POST {url} failed: {e}") from e

        if resp.status_code >= 400:
            raise ProviderError(f"Tx submission failed ({resp.status_code}): {resp.text}")

        return resp.text