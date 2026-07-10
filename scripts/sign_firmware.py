"""
Calculates the SHA-256 hash of a firmware binary and signs
that hash with the private key using RSA-PSS.
Outputs a .sig file alongside the firmware.
"""

import hashlib
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
FIRMWARE_PATH = os.path.join(BASE_DIR, "firmware", "dummy_firmware.bin")
PRIVATE_KEY_PATH = os.path.join(BASE_DIR, "keys", "private_key.pem")
SIGNATURE_OUTPUT_PATH = os.path.join(BASE_DIR, "firmware", "dummy_firmware.sig")


def calculate_sha256(filepath: str) -> bytes:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.digest()


def load_private_key(filepath: str):
    with open(filepath, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def sign_firmware():
    if not os.path.exists(PRIVATE_KEY_PATH):
        raise FileNotFoundError(
            "Private key not found. Run generate_keys.py first."
        )

    firmware_hash = calculate_sha256(FIRMWARE_PATH)
    print(f"Firmware SHA-256: {firmware_hash.hex()}")

    private_key = load_private_key(PRIVATE_KEY_PATH)

    signature = private_key.sign(
        firmware_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    with open(SIGNATURE_OUTPUT_PATH, "wb") as f:
        f.write(signature)

    print(f"Signature written to {SIGNATURE_OUTPUT_PATH}")


if __name__ == "__main__":
    sign_firmware()