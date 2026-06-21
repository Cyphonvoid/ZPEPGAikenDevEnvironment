"""
ZPEPG Bootstrap - Aiken blueprint parameterization.

Wraps `aiken blueprint apply` via subprocess, the same tool invoked
manually and confirmed working (see the original screenshot run: applying
genesis_ref's CBOR as the beacon_policy parameter, 0 errors / 0 warnings,
resulting beacon_contract.beacon_policy.mint and .else hashes matching).

WHY SHELL OUT RATHER THAN REIMPLEMENT IN PYTHON:
`aiken blueprint apply` performs UPLC term application on the compiled-but-
unparameterized validator - applying the genesis OutputReference as the
"hole" baked into beacon_policy at compile time. This is doable in pure
Python in principle (it's just UPLC application over CBOR-encoded Plutus
Data), but no Python library here implements it, and a hand-rolled
reimplementation risks subtly wrong UPLC application that silently produces
a beacon policy that does NOT actually bind to the genesis UTXO it's
supposed to. The aiken CLI is guaranteed-correct (it's the reference
implementation) and already proven working manually, so this wraps that
exact tool rather than risking a from-scratch reimplementation.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from zpepg_bootstrap.zpepg_types import OutputReference


class AikenApplyError(Exception):
    """Raised when `aiken blueprint apply` fails or produces unexpected output."""


@dataclass(frozen=True)
class AppliedBeacon:
    """Result of parameterizing beacon_policy with a genesis OutputReference."""
    beacon_policy_id_hex: str
    compiled_code_hex: str
    blueprint_path: Path


def _require_aiken_on_path() -> str:
    aiken_bin = shutil.which("aiken")
    if aiken_bin is None:
        raise AikenApplyError(
            "The `aiken` CLI was not found on PATH. Bootstrap requires the "
            "Aiken compiler to be installed and accessible (it shells out to "
            "`aiken blueprint apply` to parameterize beacon_policy - this is "
            "not reimplemented in Python; see aiken_apply.py module docstring "
            "for why). Install Aiken and ensure `aiken --version` works "
            "before retrying."
        )
    return aiken_bin


def apply_beacon_parameters(
    genesis_ref: OutputReference,
    source_blueprint_path: str | Path,
    output_blueprint_path: str | Path,
    module_title: str = "beacon_contract",
    validator_title: str = "beacon_policy",
) -> AppliedBeacon:
    """
    Run `aiken blueprint apply` to parameterize beacon_policy with the
    given genesis OutputReference, writing the resulting blueprint to
    output_blueprint_path (e.g. bootstrap_generated_plutus.json).

    Mirrors exactly the manual invocation already confirmed working:
        aiken blueprint apply \\
            -m beacon_contract \\
            -v beacon_policy \\
            -i <source_blueprint_path> \\
            -o <output_blueprint_path>
    where the CBOR-encoded genesis_ref is piped in as the parameter value
    (the manual run had this hardcoded; here it's generated from the
    OutputReference the user/picker selected).
    """
    aiken_bin = _require_aiken_on_path()

    source_blueprint_path = Path(source_blueprint_path)
    output_blueprint_path = Path(output_blueprint_path)

    if not source_blueprint_path.exists():
        raise AikenApplyError(
            f"Source blueprint not found at: {source_blueprint_path}\n"
            f"Expected a compiled plutus.json from `aiken build` for the "
            f"registry project."
        )

    param_cbor_hex = genesis_ref.to_cbor_hex()

    cmd = [
        aiken_bin,
        "blueprint",
        "apply",
        "-m", module_title,
        "-v", validator_title,
        "-i", str(source_blueprint_path),
        "-o", str(output_blueprint_path),
        param_cbor_hex,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as e:
        raise AikenApplyError(
            f"`aiken blueprint apply` timed out after 120s. Command: {' '.join(cmd)}"
        ) from e
    except OSError as e:
        raise AikenApplyError(f"Failed to invoke `aiken`: {e}") from e

    if result.returncode != 0:
        raise AikenApplyError(
            f"`aiken blueprint apply` failed (exit code {result.returncode}).\n"
            f"Command: {' '.join(cmd)}\n"
            f"--- stdout ---\n{result.stdout}\n"
            f"--- stderr ---\n{result.stderr}"
        )

    if not output_blueprint_path.exists():
        raise AikenApplyError(
            f"`aiken blueprint apply` exited successfully (code 0) but did "
            f"not produce the expected output file at {output_blueprint_path}.\n"
            f"--- stdout ---\n{result.stdout}\n"
            f"--- stderr ---\n{result.stderr}"
        )

    try:
        blueprint = json.loads(output_blueprint_path.read_text())
    except json.JSONDecodeError as e:
        raise AikenApplyError(
            f"Output blueprint at {output_blueprint_path} is not valid JSON: {e}"
        ) from e

    beacon_validator = _find_validator(
        blueprint, f"{module_title}.{validator_title}.mint"
    )
    if beacon_validator is None:
        raise AikenApplyError(
            f"Could not find validator '{module_title}.{validator_title}.mint' "
            f"in the resulting blueprint at {output_blueprint_path}. "
            f"Available validator titles: "
            f"{[v.get('title') for v in blueprint.get('validators', [])]}"
        )

    if "hash" not in beacon_validator or "compiledCode" not in beacon_validator:
        raise AikenApplyError(
            f"Beacon validator entry in resulting blueprint is missing "
            f"'hash' or 'compiledCode' field. Keys present: "
            f"{list(beacon_validator.keys())}"
        )

    return AppliedBeacon(
        beacon_policy_id_hex=beacon_validator["hash"],
        compiled_code_hex=beacon_validator["compiledCode"],
        blueprint_path=output_blueprint_path,
    )


def _find_validator(blueprint: dict, title: str) -> dict | None:
    for v in blueprint.get("validators", []):
        if v.get("title") == title:
            return v
    return None


def load_validator(blueprint_path: str | Path, title: str) -> dict:
    """Load a single validator's blueprint entry by title (e.g.
    'registry_contract.archive_registry.spend') from an already-compiled
    plutus.json. Used for the registry validator, which is NOT
    parameterized (only beacon_policy is)."""
    blueprint_path = Path(blueprint_path)
    if not blueprint_path.exists():
        raise AikenApplyError(f"Blueprint not found at: {blueprint_path}")

    try:
        blueprint = json.loads(blueprint_path.read_text())
    except json.JSONDecodeError as e:
        raise AikenApplyError(f"Blueprint at {blueprint_path} is not valid JSON: {e}") from e

    validator = _find_validator(blueprint, title)
    if validator is None:
        raise AikenApplyError(
            f"Validator '{title}' not found in blueprint at {blueprint_path}. "
            f"Available: {[v.get('title') for v in blueprint.get('validators', [])]}"
        )
    return validator