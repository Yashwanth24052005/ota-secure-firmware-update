"""
Verifies a firmware binary's signature against the public key.
Used locally to confirm the signing pipeline works correctly
before the CI/CD and edge-agent stages are built.
"""

import hashlib
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
FIRMWARE_PATH = os.path.join(BASE_DIR, "firmware", "dummy_firmware.bin")
SIGNATURE_PATH = os.path.join(BASE_DIR, "firmware", "dummy_firmware.sig")
PUBLIC_KEY_PATH = os.path.join(BASE_DIR, "keys", "public_key.pem")


def calculate_sha256(filepath: str) -> bytes:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.digest()


def load_public_key(filepath: str):
    with open(filepath, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def verify_firmware(firmware_path: str = FIRMWARE_PATH,
                     signature_path: str = SIGNATURE_PATH) -> bool:
    if not os.path.exists(firmware_path):
        raise FileNotFoundError(f"Firmware not found: {firmware_path}")
    if not os.path.exists(signature_path):
        raise FileNotFoundError(f"Signature not found: {signature_path}")
    if not os.path.exists(PUBLIC_KEY_PATH):
        raise FileNotFoundError("Public key not found. Run generate_keys.py first.")

    firmware_hash = calculate_sha256(firmware_path)
    public_key = load_public_key(PUBLIC_KEY_PATH)

    with open(signature_path, "rb") as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            firmware_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        print("Signature VALID — firmware integrity and authenticity confirmed.")
        return True
    except InvalidSignature:
        print("Signature INVALID — firmware may be tampered or corrupted. Rejecting.")
        return False


if __name__ == "__main__":
    verify_firmware()