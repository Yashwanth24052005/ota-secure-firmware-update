"""
Handles firmware version metadata. A metadata JSON file is stored
alongside each signed firmware binary, recording its version and
build timestamp — this becomes the foundation for anti-rollback
protection in Week 4.
"""

import json
import os
from datetime import datetime, timezone


def write_metadata(firmware_path: str, version: str) -> str:
    """Writes a .meta.json file next to the firmware binary."""
    metadata = {
        "version": version,
        "build_timestamp": datetime.now(timezone.utc).isoformat(),
        "firmware_file": os.path.basename(firmware_path),
    }

    metadata_path = firmware_path.replace(".bin", ".meta.json")
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)

    return metadata_path


def read_metadata(firmware_path: str) -> dict:
    metadata_path = firmware_path.replace(".bin", ".meta.json")
    if not os.path.exists(metadata_path):
        raise FileNotFoundError(f"Metadata not found: {metadata_path}")

    with open(metadata_path, "r") as f:
        return json.load(f)