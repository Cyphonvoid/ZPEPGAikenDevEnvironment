from zpepg_types import OutputReference

# Use any real tx hash/index for this test - doesn't need to be unspent yet,
# we're only checking that the CBOR encoding succeeds and looks sane
test_ref = OutputReference(
    transaction_id=bytes.fromhex("c7565416e7553cdf8fdac8bf054b4b3de19d06b72efd00c47823335d7156ed1f"),
    output_index=0,
)
print(test_ref.to_cbor_hex())