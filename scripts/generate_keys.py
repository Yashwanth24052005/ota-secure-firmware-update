"""
Generates an RSA key pair for firmware code signing.
Private key stays local (gitignored). Public key gets bundled
with the simulated edge device to verify signatures.
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "keys")
os.makedirs(KEYS_DIR, exist_ok=True)

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Serialize private key (PKCS8, unencrypted for local dev use only)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(os.path.join(KEYS_DIR, "private_key.pem"), "wb") as f:
        f.write(private_pem)

    with open(os.path.join(KEYS_DIR, "public_key.pem"), "wb") as f:
        f.write(public_pem)

    print("Key pair generated:")
    print(f" - {os.path.join(KEYS_DIR, 'private_key.pem')}")
    print(f" - {os.path.join(KEYS_DIR, 'public_key.pem')}")


if __name__ == "__main__":
    generate_key_pair()