# gen_test_keys.py
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
import struct

def to_hex(b: bytes) -> str:
    return b.hex()

# Generate authority key
priv = Ed25519PrivateKey.generate()
pub = priv.public_key()

priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

# Sign test payloads
def make_pause_payload(nonce: int) -> bytes:
    return struct.pack(">q", nonce) + b"PAUSE"

def make_resume_payload(nonce: int) -> bytes:
    return struct.pack(">q", nonce) + b"RESUME"

nonce = 0
pause_sig = priv.sign(make_pause_payload(nonce))
resume_sig = priv.sign(make_resume_payload(nonce))

print(f'// Authority key (pub): #{to_hex(pub_bytes)}')
print(f'// Authority key (priv): #{to_hex(priv_bytes)}  <- keep secret, never in contract')
print(f'// Nonce: {nonce}')
print(f'// Pause signature: #{to_hex(pause_sig)}')
print(f'// Resume signature: #{to_hex(resume_sig)}')
