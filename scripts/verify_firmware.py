"""
Verifies a firmware binary's signature against the public key.
Used locally to confirm the signing pipeline works correctly
before the CI/CD and edge-agent stages are built.
"""

import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

sys.path.insert(0, os.path.dirname(__file__))
from crypto_utils import calculate_sha256, load_public_key  # noqa: E402

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
FIRMWARE_PATH = os.path.join(BASE_DIR, "firmware", "dummy_firmware.bin")
SIGNATURE_PATH = os.path.join(BASE_DIR, "firmware", "dummy_firmware.sig")
PUBLIC_KEY_PATH = os.path.join(BASE_DIR, "keys", "public_key.pem")


def verify_firmware(firmware_path: str = FIRMWARE_PATH,
                     signature_path: str = SIGNATURE_PATH) -> bool:
    if not os.path.exists(signature_path):
        raise FileNotFoundError(f"Signature not found: {signature_path}")

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
    try:
        verify_firmware()
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        sys.exit(1)