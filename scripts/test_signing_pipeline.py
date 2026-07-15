"""
Unit tests for the firmware signing and verification pipeline.
Run with: python -m unittest scripts.test_signing_pipeline
"""

import os
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(__file__))
from crypto_utils import calculate_sha256, load_private_key, load_public_key  # noqa: E402
from generate_keys import generate_key_pair  # noqa: E402

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


class TestSigningPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Create an isolated temp directory with its own keys and firmware,
        so these tests never touch the real project's keys/firmware."""
        cls.temp_dir = tempfile.mkdtemp()
        cls.keys_dir = os.path.join(cls.temp_dir, "keys")
        os.makedirs(cls.keys_dir, exist_ok=True)

        # Generate a throwaway key pair for testing
        import generate_keys
        original_keys_dir = generate_keys.KEYS_DIR
        generate_keys.KEYS_DIR = cls.keys_dir
        generate_key_pair()
        generate_keys.KEYS_DIR = original_keys_dir

        cls.firmware_path = os.path.join(cls.temp_dir, "test_firmware.bin")
        with open(cls.firmware_path, "wb") as f:
            f.write(os.urandom(256))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_hash_is_deterministic(self):
        hash1 = calculate_sha256(self.firmware_path)
        hash2 = calculate_sha256(self.firmware_path)
        self.assertEqual(hash1, hash2)

    def test_hash_changes_when_content_changes(self):
        hash_before = calculate_sha256(self.firmware_path)
        with open(self.firmware_path, "ab") as f:
            f.write(b"extra_bytes")
        hash_after = calculate_sha256(self.firmware_path)
        # Restore original content for other tests
        with open(self.firmware_path, "rb") as f:
            content = f.read()[:-len(b"extra_bytes")]
        with open(self.firmware_path, "wb") as f:
            f.write(content)

        self.assertNotEqual(hash_before, hash_after)

    def test_missing_file_raises_error(self):
        with self.assertRaises(FileNotFoundError):
            calculate_sha256(os.path.join(self.temp_dir, "nonexistent.bin"))

    def test_sign_and_verify_roundtrip(self):
        private_key = load_private_key(os.path.join(self.keys_dir, "private_key.pem"))
        public_key = load_public_key(os.path.join(self.keys_dir, "public_key.pem"))

        firmware_hash = calculate_sha256(self.firmware_path)
        signature = private_key.sign(
            firmware_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        # Should not raise
        public_key.verify(
            signature,
            firmware_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    def test_verify_fails_on_wrong_hash(self):
        private_key = load_private_key(os.path.join(self.keys_dir, "private_key.pem"))
        public_key = load_public_key(os.path.join(self.keys_dir, "public_key.pem"))

        firmware_hash = calculate_sha256(self.firmware_path)
        signature = private_key.sign(
            firmware_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        wrong_hash = calculate_sha256.__wrapped__ if False else os.urandom(32)

        with self.assertRaises(InvalidSignature):
            public_key.verify(
                signature,
                wrong_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )


if __name__ == "__main__":
    unittest.main()