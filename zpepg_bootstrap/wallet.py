"""
ZPEPG Bootstrap - Wallet derivation and verification.

Handles the mnemonic -> address relationship for the funding/owner wallet
used to pay for and sign the genesis bootstrap transaction.

DESIGN NOTE (why this module exists in this shape):
The bootstrap script takes a mnemonic AND an address as separate inputs,
because users know their address (it's what they look at / copy / paste)
but don't know or want to track a derivation account index. Rather than
trusting that the supplied address actually corresponds to the supplied
mnemonic (which would let a mismatched pair silently build a transaction
against the wrong UTXOs, or fail signing in a confusing way deep into the
pipeline), this module SCANS a range of derivation indices, derives the
address at each one, and finds which index (if any) reproduces the
supplied address. That index is never exposed to the user - it's purely
an internal detail needed to recover the matching signing key.

If no index in the scanned range reproduces the supplied address, that's
treated as a hard error: either the address is wrong, the mnemonic is
wrong, or the account lives beyond the scan range.
"""

from __future__ import annotations

from dataclasses import dataclass

from pycardano import (
    Address,
    HDWallet,
    Network,
    PaymentExtendedSigningKey,
    PaymentVerificationKey,
    StakeExtendedSigningKey,
    StakeVerificationKey,
)

# Standard CIP-1852 derivation path for Cardano payment/stake keys:
#   m / purpose' / coin_type' / account' / role / index
# purpose' = 1852' (Shelley era), coin_type' = 1815' (Cardano, ADA's birth year)
PURPOSE = 1852
COIN_TYPE = 1815
PAYMENT_ROLE = 0
STAKE_ROLE = 2
ADDRESS_INDEX = 0  # we only ever use index 0 within a given account

# Default range of account indices to scan when resolving an address back
# to its derivation account. 0-19 matches the "gap limit" convention used
# by common Cardano wallets (Daedalus, Eternl, etc.) for account discovery.
DEFAULT_SCAN_RANGE = range(0, 20)


class AddressNotFoundError(Exception):
    """Raised when no scanned account index reproduces the supplied address."""

    def __init__(self, address: str, scan_range: range):
        self.address = address
        self.scan_range = scan_range
        super().__init__(
            f"Supplied address {address!r} does not match any account in "
            f"derivation range {scan_range.start}-{scan_range.stop - 1} for "
            f"the given mnemonic. Either the address or the mnemonic is "
            f"wrong, or the account lives outside this range (pass a wider "
            f"scan_range to widen the search)."
        )


@dataclass(frozen=True)
class DerivedAccount:
    """A single derived account: its keys and resulting address."""

    account_index: int
    payment_signing_key: PaymentExtendedSigningKey
    payment_verification_key: PaymentVerificationKey
    stake_signing_key: StakeExtendedSigningKey
    stake_verification_key: StakeVerificationKey
    address: Address

    def __repr__(self) -> str:
        # Deliberately omit signing keys from repr - this object may end up
        # in logs/debug output, and signing keys should never be printed.
        return f"DerivedAccount(account_index={self.account_index}, address={self.address})"


def derive_account(hdwallet: HDWallet, account_index: int, network: Network) -> DerivedAccount:
    """Derive payment + stake keys and the resulting address for one account index."""
    payment_path = f"m/{PURPOSE}'/{COIN_TYPE}'/{account_index}'/{PAYMENT_ROLE}/{ADDRESS_INDEX}"
    stake_path = f"m/{PURPOSE}'/{COIN_TYPE}'/{account_index}'/{STAKE_ROLE}/{ADDRESS_INDEX}"

    payment_hd = hdwallet.derive_from_path(payment_path)
    payment_esk = PaymentExtendedSigningKey.from_hdwallet(payment_hd)
    payment_evk = payment_esk.to_verification_key()

    stake_hd = hdwallet.derive_from_path(stake_path)
    stake_esk = StakeExtendedSigningKey.from_hdwallet(stake_hd)
    stake_evk = stake_esk.to_verification_key()

    address = Address(
        payment_part=payment_evk.hash(),
        staking_part=stake_evk.hash(),
        network=network,
    )

    return DerivedAccount(
        account_index=account_index,
        payment_signing_key=payment_esk,
        payment_verification_key=payment_evk,
        stake_signing_key=stake_esk,
        stake_verification_key=stake_evk,
        address=address,
    )


def resolve_wallet(
    mnemonic: str,
    expected_address: str,
    network: Network,
    scan_range: range = DEFAULT_SCAN_RANGE,
) -> DerivedAccount:
    """
    Verify that `expected_address` is derivable from `mnemonic` within
    `scan_range`, and return the matching DerivedAccount (keys + address).

    Raises AddressNotFoundError if no account index in scan_range reproduces
    the supplied address.
    """
    hdwallet = HDWallet.from_mnemonic(mnemonic)
    target = Address.from_primitive(expected_address)

    if target.network != network:
        raise ValueError(
            f"Supplied address is on network {target.network}, but bootstrap "
            f"was invoked for network {network}. Refusing to proceed - this "
            f"is almost certainly a configuration mistake."
        )

    for account_index in scan_range:
        candidate = derive_account(hdwallet, account_index, network)
        if candidate.address == target:
            return candidate

    raise AddressNotFoundError(expected_address, scan_range)