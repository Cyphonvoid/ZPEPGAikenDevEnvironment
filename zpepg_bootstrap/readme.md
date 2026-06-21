# ==============================================================================
# MODE 1: FULL INTERACTIVE SETUP
# ------------------------------------------------------------------------------
# Safely prompts your keyboard loop for sensitive credentials (mnemonic + address)
# to keep them entirely out of your terminal's shell history file (.bash_history).
# ==============================================================================
python3 -m zpepg_bootstrap --interactive


# ==============================================================================
# MODE 2: SEMI-INTERACTIVE DISCOVERY
# ------------------------------------------------------------------------------
# Mnemonic and address are supplied directly, but you omit `--genesis-ref`.
# The tool fetches and prints the live UTXO balance ledger, then blocks execution 
# with an interactive prompt asking you to choose an index as the one-shot anchor.
# ==============================================================================
python3 -m zpepg_bootstrap \
  --mnemonic "your twelve or twenty four word wallet seed phrase goes here exactly" \
  --address "addr_test1vpepg..."


# ==============================================================================
# MODE 3: FULLY NON-INTERACTIVE (REPLAY MODE)
# ------------------------------------------------------------------------------
# Everything is passed upfront. The tool verifies that your specified UTXO exists 
# and is currently unspent, applies it to Aiken, and builds/submits the genesis 
# transaction with zero prompt blocks. Perfect for automated shell scripts.
# ==============================================================================
python3 -m zpepg_bootstrap \
  --mnemonic "your twelve or twenty four word wallet seed phrase goes here exactly" \
  --address "addr_test1vpepg..." \
  --genesis-ref "aef50dba8059c69519ab632071e08b14c231985a8dba6c25cd03e0a5#0"


# ==============================================================================
# MODE 4: WALLET STATE DIAGNOSTIC (LIST-ONLY)
# ------------------------------------------------------------------------------
# Queries your active Yaci DevKit network context, pretty-logs all live UTXOs at 
# the address (TxHash#Index, Lovelace balance, and Native Assets), then cleanly 
# exits without modifying anything, compiling scripts, or creating transactions.
# ==============================================================================
python3 -m zpepg_bootstrap \
  --list-utxos \
  --mnemonic "your twelve or twenty four word wallet seed phrase goes here exactly" \
  --address "addr_test1vpepg..."