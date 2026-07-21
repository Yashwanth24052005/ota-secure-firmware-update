"""
Shared cryptographic utilities used across the signing and
verification scripts, to avoid duplicating hash/key-loading logic.
"""

import hashlib
import os
from cryptography.hazmat.primitives import serialization


def calculate_sha256(filepath: str) -> bytes:
    """Computes the SHA-256 hash of a file, reading in chunks to
    support large firmware binaries without loading them fully into memory."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.digest()


def load_private_key(filepath: str):
    if not os.path.exists(filepath):
        raise FileNotFoundError(
            f"Private key not found: {filepath}. Run generate_keys.py first."
        )
    with open(filepath, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(filepath: str):
    if not os.path.exists(filepath):
        raise FileNotFoundError(
            f"Public key not found: {filepath}. Run generate_keys.py first."
        )
    with open(filepath, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_private_key_from_env(env_var_name: str = "FIRMWARE_PRIVATE_KEY"):
    """Loads a private key from an environment variable (used in CI),
    raising a clear error if the variable isn't set."""
    key_data = os.environ.get(env_var_name)
    if not key_data:
        raise EnvironmentError(
            f"Environment variable {env_var_name} not set. "
            "This is required when running in CI."
        )
    return serialization.load_pem_private_key(
        key_data.encode(), password=None
    )