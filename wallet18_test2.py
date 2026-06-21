from pycardano import HDWallet, Network, Address
from pycardano import PaymentExtendedSigningKey, PaymentExtendedVerificationKey
from pycardano import StakeExtendedSigningKey, StakeExtendedVerificationKey

mnemonic = "test test test test test test test test test test test test test test test test test test test test test test test sauce"
hdwallet = HDWallet.from_mnemonic(mnemonic)

# Address #18, matching Yaci's derivation path numbering
hdwallet_payment = hdwallet.derive_from_path("m/1852'/1815'/18'/0/0")
payment_signing_key = PaymentExtendedSigningKey.from_hdwallet(hdwallet_payment)
payment_verification_key = payment_signing_key.to_verification_key()

hdwallet_stake = hdwallet.derive_from_path("m/1852'/1815'/18'/2/0")
stake_signing_key = StakeExtendedSigningKey.from_hdwallet(hdwallet_stake)
stake_verification_key = stake_signing_key.to_verification_key()

address = Address(
    payment_verification_key.hash(),
    stake_verification_key.hash(),
    network=Network.TESTNET,
)

EXPECTED = "addr_test1qrzufj3g0ua489yt235wtc3mrjrlucww2tqdnt7kt5rs09grsag6vxw5v053atks5a6whke03cf2qx3h3g2nhsmzwv3sgml3ed"

print("Derived address:", address)
print("Expected address:", EXPECTED)
print("Match:", str(address) == EXPECTED)