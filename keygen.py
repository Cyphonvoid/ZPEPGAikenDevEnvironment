"""
keygen.py — generates the three ZPEPG admin keypairs (authority, operator,
owner) and saves them to a JSON file under a wallet name you choose.

DEVNET / TEST USE ONLY. These are raw ed25519 keys generated and stored in
plaintext JSON for local development convenience. Do not use this approach
for mainnet keys holding real value — use a hardware wallet or a properly
secured key management approach for that.

Usage:
    python3 keygen.py

You'll be prompted for a wallet name (e.g. "zpepg-devnet-1"). Keys are
saved to keys/<wallet_name>.json. If that file already exists, you'll be
asked whether to overwrite — this is deliberate, since silently
regenerating keys you're already relying on would orphan whatever's
already been set up on-chain with the old ones (e.g. a MasterDatum
referencing the old authority_key).
"""

import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption


def generate_keypair() -> dict:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    return {
        "private_key_hex": priv_bytes.hex(),
        "public_key_hex": pub_bytes.hex(),
    }


def main():
    wallet_name = input("Wallet name (used as filename, e.g. 'zpepg-devnet-1'): ").strip()
    if not wallet_name:
        print("Wallet name cannot be empty.")
        return

    keys_dir = Path("keys")
    keys_dir.mkdir(exist_ok=True)
    out_path = keys_dir / f"{wallet_name}.json"

    if out_path.exists():
        confirm = input(
            f"{out_path} already exists. Overwriting will orphan any "
            f"on-chain state referencing these keys. Type 'overwrite' to "
            f"proceed, anything else to cancel: "
        ).strip()
        if confirm != "overwrite":
            print("Cancelled. Existing keys left untouched.")
            return

    keys = {
        "wallet_name": wallet_name,
        "authority": generate_keypair(),
        "operator": generate_keypair(),
        "owner": generate_keypair(),
    }

    with open(out_path, "w") as f:
        json.dump(keys, f, indent=2)

    # Restrict file permissions - best effort, still plaintext, still devnet-only
    os.chmod(out_path, 0o600)

    print(f"\nSaved to {out_path}")
    print("\nPublic keys (safe to share / embed in MasterDatum):")
    print(f"  authority_key (pub): {keys['authority']['public_key_hex']}")
    print(f"  operator_key  (pub): {keys['operator']['public_key_hex']}")
    print(f"  owner_key     (pub): {keys['owner']['public_key_hex']}")
    print("\nPrivate keys are saved in the JSON file only — never printed here.")
    print("Treat this file as sensitive even on devnet; don't commit it to git.")


if __name__ == "__main__":
    main()