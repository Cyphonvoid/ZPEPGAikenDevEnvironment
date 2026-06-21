"""
ZPEPG Bootstrap - Deployment tracking artifact writer.
"""

from __future__ import annotations

import json
from pathlib import Path
from zpepg_bootstrap.genesis_tx_bootstrap import GenesisTxResult

def save_deployment(result: GenesisTxResult, output_path: str | Path = "deployment.json") -> None:
    """Writes deployment details to a tracking file upon successful genesis confirmation."""
    output_path = Path(output_path)
    
    deployment_data = {
        "status": "initialized",
        "beacon_policy_id": result.beacon_policy_id,
        "beacon_asset_name_hex": result.beacon_asset_name_hex,
        "master_utxo_ref": result.master_utxo_ref,
        "registry_script_address": result.registry_script_address,
        "init_transaction_id": result.tx_id
    }
    
    output_path.write_text(json.dumps(deployment_data, indent=2))
    print(f"[✓] Deployment metadata tracking matrix committed to: {output_path}")