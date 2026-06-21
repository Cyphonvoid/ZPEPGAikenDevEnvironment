"""
ZPEPG Bootstrap - CLI Interface and Multi-Mode Dispatcher.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from pycardano import Network

from zpepg_bootstrap.wallet import resolve_wallet
from zpepg_bootstrap.perm_keys import load_permission_keys
from zpepg_bootstrap.provider import YaciStoreProvider, UtxoInfo
from zpepg_bootstrap.aiken_apply import apply_beacon_parameters
from zpepg_bootstrap.genesis_tx_bootstrap import run_genesis_transaction
from zpepg_bootstrap.deployment import save_deployment

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ZPEPG Resilient Cardano Deployment & Genesis Management System"
    )
    parser.add_argument("--interactive", action="store_true", help="Force interactive prompts")
    parser.add_argument("--mnemonic", type=str, help="Funding wallet mnemonic phrase")
    parser.add_argument("--address", type=str, help="Target wallet spending address")
    parser.add_argument("--genesis-ref", type=str, help="Specific UTXO location (tx_hash#index)")
    parser.add_argument("--list-utxos", action="store_true", help="List wallet UTXOs and exit")
    parser.add_argument("--blueprint-path", type=str, default="plutus.json", help="Path to compiled aiken plutus.json")
    parser.add_argument("--perm-keys-path", type=str, default="perm_keys.json", help="Path to operational keys config")
    parser.add_argument("--yaci-url", type=str, default="http://localhost:8080", help="Yaci Store endpoint")
    return parser.parse_args()

def run_bootstrap_cli() -> None:
    args = parse_args()
    network = Network.TESTNET 
    
    mnemonic = args.mnemonic or os.getenv("ZPEPG_MNEMONIC")
    address_str = args.address or os.getenv("ZPEPG_ADDRESS")
    genesis_ref_str = args.genesis_ref
    
    # ── ROUTING MODES ─────────────────────────────────────────────────────
    is_mode_4 = args.list_utxos
    is_mode_1 = args.interactive or (not mnemonic and not address_str and not is_mode_4)
    is_mode_3 = bool(mnemonic and address_str and genesis_ref_str and not args.interactive)
    is_mode_2 = bool(mnemonic and address_str and not genesis_ref_str and not args.interactive)

    if is_mode_1:
        print("\n=== MODE 1: FULL INTERACTIVE ===")
        if not mnemonic:
            mnemonic = input("Enter your wallet mnemonic phrase: ").strip()
        if not address_str:
            address_str = input("Enter your target verification address: ").strip()
    elif is_mode_2:
        print("\n=== MODE 2: SEMI-INTERACTIVE UTXO DISCOVERY ===")
    elif is_mode_3:
        print("\n=== MODE 3: FULLY NON-INTERACTIVE REPLAY ===")
    elif is_mode_4:
        print("\n=== MODE 4: WALLET STATE DIAGNOSTIC ===")

    if not mnemonic or not address_str:
        print("[!] Execution Failure: Both mnemonic and address must be provided.")
        sys.exit(1)

    perm_keys_path = Path(args.perm_keys_path)
    blueprint_path = Path(args.blueprint_path)
    
    if not is_mode_4:
        if not perm_keys_path.exists():
            print(f"[!] Missing operational keys file at: {perm_keys_path}")
            sys.exit(1)
        if not blueprint_path.exists():
            print(f"[!] Missing compiled Aiken blueprint file at: {blueprint_path}")
            sys.exit(1)

    # ── RESOLVE WALLET & PROVIDER ─────────────────────────────────────────
    try:
        funding_account = resolve_wallet(mnemonic, address_str, network)
    except Exception as e:
        print(f"[!] Wallet Derivation Failure: {e}")
        sys.exit(1)

    provider = YaciStoreProvider(api_base_url=args.yaci_url)

    try:
        live_utxos = provider.get_utxos(funding_account.address)
    except Exception as e:
        print(f"[!] Network Context Query Failure: {e}")
        sys.exit(1)

    if not live_utxos:
        print(f"\n[!] Ledger Error: No active UTXOs found at address: {funding_account.address}")
        sys.exit(1)

    # ── DISPLAY UTXOS (Modes 1, 2, 4) ─────────────────────────────────────
    print("\n======================================================================")
    print(f" AVAILABLE UTXOs FOR ADDRESS: {funding_account.address}")
    print("======================================================================")
    for index, utxo in enumerate(live_utxos):
        tx_hash = utxo.input.transaction_id.hex()
        out_idx = utxo.input.index
        lovelace_value = utxo.output.amount.coin
        print(f" [{index}] {tx_hash}#{out_idx}")
        print(f"     Balance: {lovelace_value} Lovelace ({lovelace_value / 1_000_000:.6f} ADA)")
        if utxo.output.amount.multi_asset:
            print(f"     Assets:  {utxo.output.amount.multi_asset}")
        print("-" * 70)

    if is_mode_4:
        print("\nMode 4 finished successfully. Exiting cleanly.")
        sys.exit(0)

    # ── TARGET SELECTION ──────────────────────────────────────────────────
    selected_utxo = None

    if is_mode_3:
        try:
            req_hash, req_idx_str = genesis_ref_str.split("#")
            req_idx = int(req_idx_str)
            for utxo in live_utxos:
                if utxo.input.transaction_id.hex() == req_hash and utxo.input.index == req_idx:
                    selected_utxo = utxo
                    break
            if not selected_utxo:
                raise ValueError(f"Requested UTXO {genesis_ref_str} is not available in wallet.")
        except Exception as e:
            print(f"[!] Target Verification Failure: {e}")
            sys.exit(1)
    else:
        while True:
            try:
                user_selection = input(f"\nSelect target index entry (0-{len(live_utxos)-1}): ").strip()
                selected_idx = int(user_selection)
                if 0 <= selected_idx < len(live_utxos):
                    selected_utxo = live_utxos[selected_idx]
                    break
                print(f"[!] Boundary mismatch. Must be 0 to {len(live_utxos)-1}.")
            except ValueError:
                print("[!] Must be a valid integer.")

    # ── PIPELINE EXECUTION ────────────────────────────────────────────────
    print(f"\nBinding parameters to anchor: {selected_utxo.input.transaction_id.hex()}#{selected_utxo.input.index}")
    
    try:
        perm_key_set = load_permission_keys(perm_keys_path)
        
        # 1. Parameterize Aiken Blueprint
        applied_beacon = apply_beacon_parameters(
            blueprint_path=blueprint_path,
            genesis_ref=selected_utxo.input,
            output_blueprint_path=blueprint_path
        )
        
        # 2. Convert PyCardano UTXO object back into the UtxoInfo expected by run_genesis_transaction
        genesis_utxo_info = UtxoInfo(
            tx_hash=selected_utxo.input.transaction_id.hex(),
            output_index=selected_utxo.input.index,
            address=str(selected_utxo.output.address),
            lovelace=selected_utxo.output.amount.coin,
            assets=[] 
        )
        
        # 3. Exactly match the run_genesis_transaction signature
        tx_result = run_genesis_transaction(
            provider=provider,
            network=network,
            funding_account=funding_account,
            genesis_utxo=genesis_utxo_info,
            beacon_compiled_code_hex=applied_beacon.beacon_compiled_code,
            beacon_policy_id_hex=applied_beacon.beacon_policy_id,
            beacon_asset_name=applied_beacon.beacon_asset_name,
            registry_compiled_code_hex=applied_beacon.registry_compiled_code,
            registry_policy_id_hex=applied_beacon.registry_policy_id,
            asset_name_prefix=applied_beacon.asset_name_prefix,
            perm_keys=perm_key_set
        )
        
        # 4. Save Artifacts
        save_deployment(tx_result)
        print("\n======================================================================")
        print(" GENESIS BOOTSTRAP INITIALIZED")
        print("======================================================================")
        print(f" Transact Hash : {tx_result.tx_id}")
        print(f" Master UTXO   : {tx_result.master_utxo_ref}")
        print(f" Registry Addr : {tx_result.registry_script_address}")
        print("======================================================================\n")

    except Exception as e:
        print(f"\n[!] Pipeline Execution Aborted: {e}")
        sys.exit(1)