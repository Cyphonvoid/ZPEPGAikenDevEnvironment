"""
Verifies Address #18's payment + staking keys derive the expected Base
address. Earlier attempt only used the payment key (-> Enterprise
address), which is why it mismatched - Yaci's default-addresses output
shows BOTH a Payment Key and a Staking Key for each address, meaning
these are Base addresses (payment credential + staking credential
combined), not Enterprise addresses (payment credential only).
"""

import bech32
from pycardano import (
    PaymentExtendedSigningKey,
    PaymentExtendedVerificationKey,
    StakeExtendedSigningKey,
    StakeExtendedVerificationKey,
    Address,
    Network,
)


def decode_extended_key_payload(bech32_str: str) -> bytes:
    hrp, data_5bit = bech32.bech32_decode(bech32_str)
    if data_5bit is None:
        raise ValueError(f"bech32 decode failed for key starting with {bech32_str[:15]}...")
    payload = bech32.convertbits(data_5bit, 5, 8, False)
    return bytes(payload)


# ── Paste both keys here ───────────────────────────────────────────────
PAYMENT_KEY_BECH32 = "ed25519e_sk1ppu7cwx5vd8he3eck6e796t3ucnpqe4z8672x6h32khrjsh2t3dnq2f6qvyp3p3gtmgchw0jdseu57296pdlre3mql98vcgdy50hxsgfn77s3"
STAKING_KEY_BECH32 = "ed25519e_sk14q9d4kyagaa5glcj938xhsdhhrze2747dmjfupww4833yw82t3d5ek5emhyn7vn4qumdqzkqleqma3q4lks4mfhfqfnww8szm9u2wfs7v99es"

EXPECTED_ADDRESS = "addr_test1qrzufj3g0ua489yt235wtc3mrjrlucww2tqdnt7kt5rs09grsag6vxw5v053atks5a6whke03cf2qx3h3g2nhsmzwv3sgml3ed"
EXPECTED_STAKE_ADDRESS = "stake_test1uqpcw5dxr82x86g74mg2wa8tmvhcuy4qrgmc59fmcd38xgcmfuasu"


def main():
    if "PASTE" in PAYMENT_KEY_BECH32 or "PASTE" in STAKING_KEY_BECH32:
        print("Edit this file and paste both real Bech32 keys first.")
        return

    payment_payload = decode_extended_key_payload(PAYMENT_KEY_BECH32)
    staking_payload = decode_extended_key_payload(STAKING_KEY_BECH32)
    print(f"payment payload length: {len(payment_payload)} bytes")
    print(f"staking payload length: {len(staking_payload)} bytes")

    payment_esk = PaymentExtendedSigningKey(payment_payload)
    payment_evk = PaymentExtendedVerificationKey.from_signing_key(payment_esk)

    staking_esk = StakeExtendedSigningKey(staking_payload)
    staking_evk = StakeExtendedVerificationKey.from_signing_key(staking_esk)

    base_address = Address(
        payment_part=payment_evk.hash(),
        staking_part=staking_evk.hash(),
        network=Network.TESTNET,
    )

    stake_address = Address(
        payment_part=None,
        staking_part=staking_evk.hash(),
        network=Network.TESTNET,
    )

    print(f"\nDerived base address:  {base_address}")
    print(f"Expected base address: {EXPECTED_ADDRESS}")
    print(f"Base address match: {str(base_address) == EXPECTED_ADDRESS}")

    print(f"\nDerived stake address:  {stake_address}")
    print(f"Expected stake address: {EXPECTED_STAKE_ADDRESS}")
    print(f"Stake address match: {str(stake_address) == EXPECTED_STAKE_ADDRESS}")


if __name__ == "__main__":
    main()