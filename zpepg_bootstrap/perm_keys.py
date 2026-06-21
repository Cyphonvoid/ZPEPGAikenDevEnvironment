"""
ZPEPG Bootstrap - Permission key set loading (perm_keys.json).

The permission key set (authority / operator / owner) is conceptually
SEPARATE from the funding/owner wallet handled in wallet.py:

  - wallet.py's DerivedAccount is the mnemonic-derived wallet that PAYS for
    and SIGNS the genesis transaction, and supplies owner_address in
    MasterDatum.
  - perm_keys.json's three keypairs are bare Ed25519 keys with NO address
    of their own. They are written into MasterDatum as authority_key /
    operator_key / owner_key (VerificationKey fields only) and are checked
    on-chain later via verify_ed25519_signature against Signatures supplied
    in future redeemers (RotateKey, Pause, MintDocument, etc.) - see
    archive_registry.ak. Bootstrap never signs anything with these keys;
    it only needs their PUBLIC halves to populate the genesis datum.

The private key halves are read (so the file's structure can be validated
up front and fail loudly if malformed) but are deliberately discarded
immediately after validation - see PermKeySet.public_keys_only(). Bootstrap
must never log, print, or persist private_key_hex anywhere.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REQUIRED_ROLES = ("authority", "operator", "owner")
REQUIRED_FIELDS = ("private_key_hex", "public_key_hex")

EXAMPLE_STRUCTURE = """{
  "authority": {
    "private_key_hex": "<64 hex chars (32 bytes) ed25519 private key>",
    "public_key_hex": "<64 hex chars (32 bytes) ed25519 public key>"
  },
  "operator": {
    "private_key_hex": "<64 hex chars (32 bytes) ed25519 private key>",
    "public_key_hex": "<64 hex chars (32 bytes) ed25519 public key>"
  },
  "owner": {
    "private_key_hex": "<64 hex chars (32 bytes) ed25519 private key>",
    "public_key_hex": "<64 hex chars (32 bytes) ed25519 public key>"
  }
}"""


class PermKeysError(Exception):
    """Raised for any perm_keys.json loading/validation failure. Always
    includes the expected structure so the user can fix the file without
    needing to read source code."""

    def __init__(self, reason: str):
        super().__init__(
            f"{reason}\n\n"
            f"perm_keys.json must have exactly this structure "
            f"(hex strings, 32 bytes / 64 hex chars each):\n\n"
            f"{EXAMPLE_STRUCTURE}"
        )


@dataclass(frozen=True)
class RolePublicKey:
    role: str
    public_key_bytes: bytes

    @property
    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()


@dataclass(frozen=True)
class PermKeySet:
    """Public-only view of the permission key set. This is the ONLY form
    of the permission keys that should ever flow into datum-building code,
    logs, or deployment.json."""

    authority: RolePublicKey
    operator: RolePublicKey
    owner: RolePublicKey

    def as_dict(self) -> dict[str, str]:
        """Public keys only, safe to log / persist / embed in deployment.json."""
        return {
            "authority_key": self.authority.public_key_hex,
            "operator_key": self.operator.public_key_hex,
            "owner_key": self.owner.public_key_hex,
        }


def _validate_hex_field(role: str, field: str, value: Any) -> bytes:
    if not isinstance(value, str):
        raise PermKeysError(
            f"perm_keys.json field '{role}.{field}' must be a hex string, "
            f"got {type(value).__name__}."
        )
    try:
        raw = bytes.fromhex(value)
    except ValueError as e:
        raise PermKeysError(
            f"perm_keys.json field '{role}.{field}' is not valid hex: {e}"
        ) from e
    if len(raw) != 32:
        raise PermKeysError(
            f"perm_keys.json field '{role}.{field}' must be 32 bytes "
            f"(64 hex chars) for an Ed25519 key, got {len(raw)} bytes."
        )
    return raw


def load_permission_keys(path: str | Path) -> PermKeySet:
    """
    Load and validate perm_keys.json, returning ONLY the public keys.

    Raises PermKeysError (with the expected structure included in the
    message) if the file is missing, malformed, or incomplete.
    """
    path = Path(path)

    if not path.exists():
        raise PermKeysError(
            f"perm_keys.json not found at: {path}\n"
            f"Bootstrap requires a permission key set file at this path."
        )

    try:
        raw_text = path.read_text()
    except OSError as e:
        raise PermKeysError(f"Could not read perm_keys.json at {path}: {e}") from e

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        raise PermKeysError(f"perm_keys.json at {path} is not valid JSON: {e}") from e

    if not isinstance(data, dict):
        raise PermKeysError(
            f"perm_keys.json must contain a JSON object at the top level, "
            f"got {type(data).__name__}."
        )

    missing_roles = [r for r in REQUIRED_ROLES if r not in data]
    if missing_roles:
        raise PermKeysError(
            f"perm_keys.json is missing required role(s): {', '.join(missing_roles)}"
        )

    role_public_keys: dict[str, RolePublicKey] = {}

    for role in REQUIRED_ROLES:
        role_data = data[role]
        if not isinstance(role_data, dict):
            raise PermKeysError(
                f"perm_keys.json field '{role}' must be an object, "
                f"got {type(role_data).__name__}."
            )

        missing_fields = [f for f in REQUIRED_FIELDS if f not in role_data]
        if missing_fields:
            raise PermKeysError(
                f"perm_keys.json role '{role}' is missing required "
                f"field(s): {', '.join(missing_fields)}"
            )

        # Validate private_key_hex structurally (fail loudly if malformed)
        # but discard it immediately - it is never used by bootstrap and
        # must never be retained beyond this validation step.
        _validate_hex_field(role, "private_key_hex", role_data["private_key_hex"])
        del role_data  # extra emphasis: nothing below this line touches private_key_hex

        public_key_bytes = _validate_hex_field(
            role, "public_key_hex", data[role]["public_key_hex"]
        )
        role_public_keys[role] = RolePublicKey(role=role, public_key_bytes=public_key_bytes)

    return PermKeySet(
        authority=role_public_keys["authority"],
        operator=role_public_keys["operator"],
        owner=role_public_keys["owner"],
    )