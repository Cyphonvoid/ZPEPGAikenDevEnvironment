"""
cardano_network.py - Network backend abstraction for ZPEPG deployment.

YaciDevNetApi is the concrete provider for local Yaci DevKit / Yaci Store.
Swap for a Blockfrost-backed implementation later without touching workflow code.

Wire format notes (confirmed against actual server behavior, do not simplify):
  - /api/v1/utils/txs/evaluate  expects hex-encoded CBOR text as body
  - /api/v1/tx/submit           expects raw binary CBOR as body
  - /api/v1/addresses/.../utxos fetched directly (pccontext has KeyError bug)
  - /api/v1/epochs/.../parameters fetched directly (pccontext returns null cost_models)
  - /api/v1/blocks/latest       fetched directly (pccontext raises NotImplementedError)
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Protocol, runtime_checkable

import requests
from pycardano import ExecutionUnits, ProtocolParameters


# ── Data types ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class UtxoAsset:
    unit: str      # "lovelace" or policy_id+asset_name hex
    quantity: int


@dataclass(frozen=True)
class UtxoInfo:
    tx_hash: str
    output_index: int
    address: str
    lovelace: int
    assets: tuple[UtxoAsset, ...]

    @property
    def ref_str(self) -> str:
        return f"{self.tx_hash}#{self.output_index}"

    def format_summary(self) -> str:
        ada = self.lovelace / 1_000_000
        asset_part = f", {len(self.assets)} native asset(s)" if self.assets else ""
        return f"{self.ref_str}  ({ada:.6f} ADA{asset_part})"


class NetworkError(Exception):
    """Raised for any provider-level failure."""


# ── Provider protocol ─────────────────────────────────────────────────────

@runtime_checkable
class NetworkBackend(Protocol):
    def get_utxos(self, address: str) -> list[UtxoInfo]: ...
    def find_utxo(self, address: str, tx_hash: str, output_index: int) -> UtxoInfo | None: ...
    def current_slot(self) -> int: ...
    def protocol_parameters(self) -> ProtocolParameters: ...
    def evaluate_tx(self, tx_cbor: bytes) -> dict[str, ExecutionUnits]: ...
    def submit_tx(self, tx_cbor: bytes) -> str: ...


# ── Yaci DevKit / Yaci Store implementation ───────────────────────────────

class YaciDevNetApi:

    DEFAULT_URL = "http://localhost:8080"

    def __init__(self, base_url: str = DEFAULT_URL):
        self.base_url = base_url.rstrip("/")

    # ── internal ──────────────────────────────────────────────────────────

    def _get(self, path: str) -> dict | list:
        url = f"{self.base_url}{path}"
        try:
            resp = requests.get(url)
            resp.raise_for_status()
        except requests.RequestException as e:
            raise NetworkError(f"GET {url} failed: {e}") from e
        return resp.json()

    def _post(self, path: str, data: bytes | str, content_type: str) -> requests.Response:
        url = f"{self.base_url}{path}"
        try:
            resp = requests.post(url, data=data, headers={"Content-Type": content_type})
        except requests.RequestException as e:
            raise NetworkError(f"POST {url} failed: {e}") from e
        if resp.status_code >= 400:
            raise NetworkError(f"POST {url} returned {resp.status_code}: {resp.text}")
        return resp

    # ── NetworkBackend interface ───────────────────────────────────────────

    def get_utxos(self, address: str) -> list[UtxoInfo]:
        raw = self._get(f"/api/v1/addresses/{address}/utxos")
        if not isinstance(raw, list):
            raise NetworkError(f"Unexpected response shape from utxos endpoint: {type(raw)}")
        results = []
        for item in raw:
            lovelace = 0
            assets = []
            for a in item.get("amount", []):
                if a["unit"] == "lovelace":
                    lovelace = int(a["quantity"])
                else:
                    assets.append(UtxoAsset(unit=a["unit"], quantity=int(a["quantity"])))
            results.append(UtxoInfo(
                tx_hash=item["tx_hash"],
                output_index=item["output_index"],
                address=item.get("address", address),
                lovelace=lovelace,
                assets=tuple(assets),
            ))
        return results

    def find_utxo(self, address: str, tx_hash: str, output_index: int) -> UtxoInfo | None:
        return next(
            (u for u in self.get_utxos(address)
             if u.tx_hash == tx_hash and u.output_index == output_index),
            None,
        )

    def current_slot(self) -> int:
        data = self._get("/api/v1/blocks/latest")
        if "slot" not in data:
            raise NetworkError(f"/blocks/latest missing 'slot': {data}")
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
                decentralization_param=Fraction(0),
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
            raise NetworkError(f"protocol_parameters response missing field: {e}") from e

    def evaluate_tx(self, tx_cbor: bytes) -> dict[str, ExecutionUnits]:
        # Confirmed wire format: hex-encoded CBOR text, NOT raw bytes
        resp = self._post("/api/v1/utils/txs/evaluate", tx_cbor.hex(), "application/cbor")
        result = resp.json()
        eval_result = result.get("result", {}).get("EvaluationResult")
        if not eval_result:
            raise NetworkError(f"Script evaluation failed: {result}")
        return {
            k: ExecutionUnits(mem=v["memory"], steps=v["steps"])
            for k, v in eval_result.items()
        }

    def submit_tx(self, tx_cbor: bytes) -> str:
        # Confirmed wire format: raw binary CBOR (opposite of evaluate_tx)
        resp = self._post("/api/v1/tx/submit", tx_cbor, "application/cbor")
        return resp.text
