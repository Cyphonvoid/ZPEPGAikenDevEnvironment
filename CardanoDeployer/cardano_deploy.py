"""
cardano_deploy.py - CLI entry point for ZPEPG deployment utility.

This file owns ONLY:
  - CLI argument parsing
  - Input gathering (prompts, env vars, arg reading)
  - The four deployment modes (as input-gathering strategies)
  - Calling into cardano_workflow.py with fully-resolved inputs

It does NOT own any deployment logic itself.

Four modes:
  1. FULL INTERACTIVE   --interactive or no args
  2. SEMI-INTERACTIVE   --address supplied, no --genesis-ref (UTXO picker runs)
  3. NON-INTERACTIVE    --address + --genesis-ref (replay/automation, zero prompts)
  4. LIST-ONLY          --list-utxos (prints UTXOs and exits, no deployment)

Mnemonic is never accepted as a bare CLI arg (would land in shell history).
Supply via ZPEPG_MNEMONIC env var or hidden prompt.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from pycardano import Network

from cardano_network import YaciDevNetApi, NetworkError, UtxoInfo
from cardano_types import OutputReference
from cardano_workflow import (
    AikenBlueprint, DeploymentRecord, GenesisTransaction, PermKeys, Wallet,
)

# ── Global constants (genuinely needed by multiple parts of this file) ────

MNEMONIC_ENV_VAR = "ZPEPG_MNEMONIC"

BEACON_ASSET_NAME        = b"ZPEPG-BEACON-TEST"
REGISTRY_ASSET_NAME_PREFIX = b"ZPEPG-ARCHIVE-DOC"

NETWORK_MAP = {
    "devnet":   Network.TESTNET,
    "preview":  Network.TESTNET,
    "preprod":  Network.TESTNET,
    "mainnet":  Network.MAINNET,
}


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

class CLI:
    """
    Namespace for CLI argument parsing and input-gathering helpers.
    All methods are classmethods / staticmethods - no instantiation.
    """

    class Error(Exception):
        """User-facing error: printed cleanly without traceback."""

    @classmethod
    def build_parser(cls) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="cardano-deploy",
            description=(
                "ZPEPG Cardano deployment utility. "
                "Handles genesis bootstrap: parameterize beacon_policy, "
                "mint the beacon token, create the first master UTXO."
            ),
        )
        parser.add_argument(
            "--interactive", action="store_true",
            help="Force full interactive mode (prompts for all inputs).",
        )
        parser.add_argument(
            "--list-utxos", action="store_true",
            help="List UTXOs at the wallet address and exit without deploying.",
        )
        parser.add_argument(
            "--address",
            help="Funding/owner wallet address.",
        )
        parser.add_argument(
            "--genesis-ref", metavar="TX_HASH#INDEX",
            help="Genesis UTXO as tx_hash#index. If omitted, interactive UTXO picker runs.",
        )
        parser.add_argument(
            "--network", choices=sorted(NETWORK_MAP.keys()), default="devnet",
            help="Target network (default: devnet).",
        )
        parser.add_argument(
            "--provider-url", default=YaciDevNetApi.DEFAULT_URL,
            help=f"Yaci Store base URL (default: {YaciDevNetApi.DEFAULT_URL}).",
        )
        parser.add_argument(
            "--perm-keys", default="perm_keys.json",
            help="Path to perm_keys.json (default: perm_keys.json).",
        )
        parser.add_argument(
            "--source-blueprint", default="zpepg_aiken_registry/plutus.json",
            help="Path to unparameterized plutus.json from `aiken build`.",
        )
        parser.add_argument(
            "--output-blueprint", default="bootstrap_generated_plutus.json",
            help="Output path for the parameterized blueprint.",
        )
        parser.add_argument(
            "--deployment-json", default="deployment.json",
            help="Output path for the deployment record (default: deployment.json).",
        )
        parser.add_argument(
            "--scan-limit", type=int, default=20,
            help="Derivation account scan range when verifying address (default: 20).",
        )
        parser.add_argument(
            "--overwrite", action="store_true",
            help="Allow overwriting an existing deployment.json.",
        )
        return parser

    @staticmethod
    def get_mnemonic() -> str:
        mnemonic = os.environ.get(MNEMONIC_ENV_VAR, "").strip()
        if mnemonic:
            print(f"[Using mnemonic from {MNEMONIC_ENV_VAR}]")
            return mnemonic
        mnemonic = getpass.getpass("Mnemonic (hidden): ").strip()
        if not mnemonic:
            raise CLI.Error("No mnemonic provided.")
        return mnemonic

    @staticmethod
    def get_address() -> str:
        address = input("Wallet address: ").strip()
        if not address:
            raise CLI.Error("No address provided.")
        return address

    @staticmethod
    def parse_genesis_ref(ref_str: str) -> tuple[str, int]:
        parts = ref_str.split("#")
        if len(parts) != 2:
            raise CLI.Error(
                f"Invalid --genesis-ref: {ref_str!r}. Expected tx_hash#index."
            )
        tx_hash, index_str = parts
        if len(tx_hash) != 64:
            raise CLI.Error(f"tx_hash must be 64 hex chars, got {len(tx_hash)}.")
        try:
            bytes.fromhex(tx_hash)
        except ValueError as e:
            raise CLI.Error(f"tx_hash is not valid hex: {e}") from e
        try:
            index = int(index_str)
            assert index >= 0
        except (ValueError, AssertionError):
            raise CLI.Error(f"UTXO index must be a non-negative integer, got {index_str!r}.")
        return tx_hash, index

    @staticmethod
    def print_utxos(utxos: list[UtxoInfo]) -> None:
        if not utxos:
            print("  (no UTXOs found)")
            return
        for i, u in enumerate(utxos):
            ada = u.lovelace / 1_000_000
            asset_part = f"  + {len(u.assets)} native asset(s)" if u.assets else ""
            print(f"  [{i}]  {u.tx_hash}#{u.output_index}  {ada:.6f} ADA{asset_part}")

    @staticmethod
    def pick_utxo(utxos: list[UtxoInfo]) -> UtxoInfo:
        if not utxos:
            raise CLI.Error("No UTXOs available at this address.")
        print("\nUTXOs at this address:")
        CLI.print_utxos(utxos)
        while True:
            raw = input(f"\nSelect genesis UTXO index [0-{len(utxos)-1}]: ").strip()
            if not raw:
                raise CLI.Error("No selection made.")
            try:
                idx = int(raw)
            except ValueError:
                print(f"  Enter a number between 0 and {len(utxos)-1}.")
                continue
            if 0 <= idx < len(utxos):
                selected = utxos[idx]
                print(f"\nSelected: {selected.format_summary()}")
                if input("Confirm? [y/N]: ").strip().lower() == "y":
                    return selected
                print("Cancelled. Try again.")
            else:
                print(f"  Index out of range.")

    @staticmethod
    def resolve_wallet(mnemonic: str, address: str, network: Network, scan_limit: int) -> "Wallet.DerivedAccount":
        print(f"\n--- Verifying address (scanning accounts 0-{scan_limit-1}) ---")
        try:
            account = Wallet.resolve(mnemonic, address, network, scan_range=range(0, scan_limit))
        except Wallet.NotFoundError as e:
            raise CLI.Error(str(e)) from e
        except Exception as e:
            raise CLI.Error(f"Wallet derivation failed: {e}") from e
        print(f"  Verified: account {account.account_index}, address {account.address}")
        return account


# ═══════════════════════════════════════════════════════════════════════════
# Deployment workflow runner (calls into cardano_workflow.py)
# ═══════════════════════════════════════════════════════════════════════════

def run_deployment(
    account: "Wallet.DerivedAccount",
    genesis_utxo: UtxoInfo,
    network: Network,
    backend: YaciDevNetApi,
    args: argparse.Namespace,
) -> None:
    """
    Execute the full deployment workflow once inputs are resolved.
    Shared by modes 1, 2, and 3.
    """
    print("\n--- Loading permission keys ---")
    try:
        perm_keys = PermKeys.load(args.perm_keys)
    except PermKeys.Error as e:
        raise CLI.Error(str(e)) from e
    print(f"  authority: {perm_keys.authority_key.hex()}")
    print(f"  operator:  {perm_keys.operator_key.hex()}")
    print(f"  owner:     {perm_keys.owner_key.hex()}")

    print("\n--- Parameterizing beacon_policy ---")
    genesis_output_ref = OutputReference(
        transaction_id=bytes.fromhex(genesis_utxo.tx_hash),
        output_index=genesis_utxo.output_index,
    )
    print(f"  Genesis ref CBOR: {genesis_output_ref.to_cbor_hex()}")
    try:
        applied = AikenBlueprint.apply_beacon_parameter(
            genesis_ref=genesis_output_ref,
            source_blueprint_path=args.source_blueprint,
            output_blueprint_path=args.output_blueprint,
        )
    except AikenBlueprint.Error as e:
        raise CLI.Error(str(e)) from e
    print(f"  Beacon policy ID: {applied.beacon_policy_id_hex}")

    print("\n--- Loading registry validator ---")
    try:
        registry_validator = AikenBlueprint.load_registry_validator(args.output_blueprint)
    except AikenBlueprint.Error as e:
        raise CLI.Error(str(e)) from e
    print(f"  Registry policy ID: {registry_validator['hash']}")

    print("\n--- Building and submitting genesis transaction ---")
    try:
        tx_result = GenesisTransaction.run(
            backend=backend,
            network=network,
            funding_account=account,
            genesis_utxo=genesis_utxo,
            beacon_compiled_code_hex=applied.compiled_code_hex,
            beacon_policy_id_hex=applied.beacon_policy_id_hex,
            beacon_asset_name=BEACON_ASSET_NAME,
            registry_compiled_code_hex=registry_validator["compiledCode"],
            registry_policy_id_hex=registry_validator["hash"],
            asset_name_prefix=REGISTRY_ASSET_NAME_PREFIX,
            perm_keys=perm_keys,
        )
    except GenesisTransaction.Error as e:
        raise CLI.Error(str(e)) from e

    print(f"\n  SUCCESS")
    print(f"  Genesis tx ID:    {tx_result.tx_id}")
    print(f"  Master UTXO:      {tx_result.master_utxo_ref}")
    print(f"  Registry address: {tx_result.registry_script_address}")

    print("\n--- Writing deployment.json ---")
    record = DeploymentRecord.build(
        network=network,
        funding_account=account,
        genesis_utxo=genesis_utxo,
        tx_result=tx_result,
        beacon_asset_name=BEACON_ASSET_NAME,
        perm_keys=perm_keys,
        blueprint_output_path=args.output_blueprint,
    )
    try:
        #written = DeploymentRecord.write(record, args.deployment_json, allow_overwrite=args.overwrite)
        written = DeploymentRecord.write(record, args.deployment_json, allow_overwrite=True)

    except DeploymentRecord.Error as e:
        raise CLI.Error(str(e)) from e

    print(f"  Written: {written}")
    print("\n=== Deployment complete ===")
    print(f"  Beacon policy ID:     {tx_result.beacon_policy_id_hex}")
    print(f"  Registry policy ID:   {tx_result.registry_policy_id_hex}")
    print(f"  Registry address:     {tx_result.registry_script_address}")
    print(f"  Master UTXO:          {tx_result.master_utxo_ref}")
    print(f"  Deployment record:    {written}")


# ═══════════════════════════════════════════════════════════════════════════
# main() - four-mode dispatch
# ═══════════════════════════════════════════════════════════════════════════

def main(argv=None) -> int:
    parser = CLI.build_parser()
    args = parser.parse_args(argv)

    network = NETWORK_MAP[args.network]
    backend = YaciDevNetApi(args.provider_url)

    try:
        # ── MODE 4: LIST-ONLY ─────────────────────────────────────────────
        if args.list_utxos:
            if not args.address:
                args.address = CLI.get_address()
            mnemonic = CLI.get_mnemonic()
            account = CLI.resolve_wallet(mnemonic, args.address, network, args.scan_limit)
            print(f"\nFetching UTXOs for {account.address} ...")
            utxos = backend.get_utxos(str(account.address))
            print(f"\nUTXOs at {account.address}:")
            CLI.print_utxos(utxos)
            return 0

        # ── MODE 1: FULL INTERACTIVE ──────────────────────────────────────
        if args.interactive or (not args.address):
            print("=== ZPEPG Cardano Deployment - Interactive Mode ===\n")
            mnemonic = CLI.get_mnemonic()
            address = CLI.get_address()
            account = CLI.resolve_wallet(mnemonic, address, network, args.scan_limit)
            print(f"\nFetching UTXOs ...")
            utxos = backend.get_utxos(str(account.address))
            genesis_utxo = CLI.pick_utxo(utxos)
            run_deployment(account, genesis_utxo, network, backend, args)
            return 0

        # ── MODES 2 & 3: address is present ──────────────────────────────
        mnemonic = CLI.get_mnemonic()
        account = CLI.resolve_wallet(mnemonic, args.address, network, args.scan_limit)
        print(f"\nFetching UTXOs ...")
        utxos = backend.get_utxos(str(account.address))

        # ── MODE 3: NON-INTERACTIVE ───────────────────────────────────────
        if args.genesis_ref:
            tx_hash, output_index = CLI.parse_genesis_ref(args.genesis_ref)
            genesis_utxo = next(
                (u for u in utxos if u.tx_hash == tx_hash and u.output_index == output_index),
                None,
            )
            if genesis_utxo is None:
                print(
                    f"Error: UTXO {args.genesis_ref} not found at {account.address}.",
                    file=sys.stderr,
                )
                return 1
            print(f"  Confirmed: {genesis_utxo.format_summary()}")
            run_deployment(account, genesis_utxo, network, backend, args)
            return 0

        # ── MODE 2: SEMI-INTERACTIVE ──────────────────────────────────────
        genesis_utxo = CLI.pick_utxo(utxos)
        run_deployment(account, genesis_utxo, network, backend, args)
        return 0

    except CLI.Error as e:
        print(f"\nError: {e}", file=sys.stderr)
        return 1
    except NetworkError as e:
        print(f"\nNetwork error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
