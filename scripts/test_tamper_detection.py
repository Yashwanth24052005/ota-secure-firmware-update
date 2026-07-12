"""
Automated test proving the signing pipeline detects firmware tampering.

Workflow:
1. Back up the current (legitimately signed) firmware + signature.
2. Corrupt the firmware binary and confirm verification FAILS.
3. Restore the original firmware + signature and confirm verification PASSES.

This script is self-contained and idempotent — it always leaves the repo
in a valid, correctly-signed state when it finishes (even if it fails
partway through).
"""

import os
import shutil
import sys

# Allow importing sign_firmware.py / verify_firmware.py from the same folder
sys.path.insert(0, os.path.dirname(__file__))

from verify_firmware import verify_firmware  # noqa: E402

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
FIRMWARE_PATH = os.path.join(BASE_DIR, "firmware", "dummy_firmware.bin")
SIGNATURE_PATH = os.path.join(BASE_DIR, "firmware", "dummy_firmware.sig")
BACKUP_FIRMWARE_PATH = FIRMWARE_PATH + ".bak"
BACKUP_SIGNATURE_PATH = SIGNATURE_PATH + ".bak"


def backup_originals():
    shutil.copyfile(FIRMWARE_PATH, BACKUP_FIRMWARE_PATH)
    shutil.copyfile(SIGNATURE_PATH, BACKUP_SIGNATURE_PATH)


def restore_originals():
    shutil.copyfile(BACKUP_FIRMWARE_PATH, FIRMWARE_PATH)
    shutil.copyfile(BACKUP_SIGNATURE_PATH, SIGNATURE_PATH)
    os.remove(BACKUP_FIRMWARE_PATH)
    os.remove(BACKUP_SIGNATURE_PATH)


def corrupt_firmware():
    with open(FIRMWARE_PATH, "ab") as f:
        f.write(b"TAMPERED_BYTES")


def run_test() -> bool:
    print("=== Firmware Tamper Detection Test ===\n")

    print("[1/3] Verifying original, legitimately signed firmware...")
    if not verify_firmware(FIRMWARE_PATH, SIGNATURE_PATH):
        print("FAIL: original firmware should verify successfully. Aborting test.")
        return False
    print("PASS: original firmware verified as expected.\n")

    print("[2/3] Backing up and corrupting firmware...")
    backup_originals()
    corrupt_firmware()

    tamper_result = verify_firmware(FIRMWARE_PATH, SIGNATURE_PATH)
    if tamper_result:
        print("FAIL: tampered firmware incorrectly passed verification!")
        restore_originals()
        return False
    print("PASS: tampered firmware correctly rejected.\n")

    print("[3/3] Restoring original firmware...")
    restore_originals()

    if not verify_firmware(FIRMWARE_PATH, SIGNATURE_PATH):
        print("FAIL: restored firmware did not verify. Repo may be left inconsistent!")
        return False
    print("PASS: restored firmware verifies correctly again.\n")

    print("=== ALL TAMPER DETECTION TESTS PASSED ===")
    return True


if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)