import hashlib
import bech32

def asset_fingerprint(policy_id: bytes, asset_name: bytes) -> str:
    """
    CIP-14 user-facing asset fingerprint: bech32-encoded blake2b-160 digest
    of the concatenation of raw policy_id and asset_name bytes (NOT their
    hex string forms - the spec explicitly requires decoded raw bytes).
    """
    digest = hashlib.blake2b(policy_id + asset_name, digest_size=20).digest()
    words = bech32.convertbits(digest, 8, 5)
    return bech32.bech32_encode("asset", words)


# ── CIP-14 official test vectors ─────────────────────────────────────────
test_vectors = [
    ("7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373", "", "asset1rjklcrnsdzqp65wjgrg55sy9723kw09mlgvlc3"),
    ("7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc37e", "", "asset1nl0puwxmhas8fawxp8nx4e2q3wekg969n2auw3"),
    ("1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209", "", "asset1uyuxku60yqe57nusqzjx38aan3f2wq6s93f6ea"),
    ("7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373", "504154415445", "asset13n25uv0yaf5kus35fm2k86cqy60z58d9xmde92"),
    ("1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209", "504154415445", "asset1hv4p5tv2a837mzqrst04d0dcptdjmluqvdx9k3"),
]

all_passed = True
for policy_hex, name_hex, expected in test_vectors:
    result = asset_fingerprint(bytes.fromhex(policy_hex), bytes.fromhex(name_hex))
    status = "PASS" if result == expected else "FAIL"
    if result != expected:
        all_passed = False
    print(f"{status}  expected={expected}  got={result}")

print()
print("ALL PASSED" if all_passed else "SOME FAILED - DO NOT USE THIS IMPLEMENTATION")