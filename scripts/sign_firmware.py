"""
Calculates the SHA-256 hash of a firmware binary and signs
that hash with the private key using RSA-PSS.
Outputs a .sig file alongside the firmware, plus a .meta.json
file recording the firmware version and build timestamp.
"""

import argparse
import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

sys.path.insert(0, os.path.dirname(__file__))
from crypto_utils import calculate_sha256, load_private_key  # noqa: E402
from firmware_metadata import write_metadata  # noqa: E402

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
FIRMWARE_PATH = os.path.join(BASE_DIR, "firmware", "dummy_firmware.bin")
PRIVATE_KEY_PATH = os.path.join(BASE_DIR, "keys", "private_key.pem")
SIGNATURE_OUTPUT_PATH = os.path.join(BASE_DIR, "firmware", "dummy_firmware.sig")


def sign_firmware():
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
    parser = argparse.ArgumentParser(description="Sign a firmware binary.")
    parser.add_argument(
        "--version",
        default="1.0.0",
        help="Firmware version tag (e.g., 1.0.1)",
    )
    args = parser.parse_args()

    try:
        sign_firmware()
        metadata_path = write_metadata(FIRMWARE_PATH, args.version)
        print(f"Metadata written to {metadata_path} (version {args.version})")
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        sys.exit(1)