![Sign Firmware CI](https://github.com/Yashwanth24052005/ota-secure-firmware-update/actions/workflows/sign-firmware.yml/badge.svg)

# Secure OTA Firmware Update & Code Signing Infrastructure

A secure Over-The-Air (OTA) firmware update framework for IoT edge devices, built as
part of the Infotact Advanced Cybersecurity Internship Program (Logistics & IoT Edge track).

## Problem Statement

IoT fleets that receive firmware updates over the air are vulnerable to man-in-the-middle
and supply-chain attacks: if an attacker intercepts an update and substitutes malicious
firmware, they can compromise the entire device fleet. This project builds a code-signing
and verification pipeline that guarantees firmware authenticity and integrity before
installation, and prevents forced downgrades to vulnerable versions.

## Threat Model

**Assets protected:** firmware binaries in transit and at rest on the distribution server;
the private signing key; the integrity of the edge device's installed firmware version.

**Adversary capabilities assumed:**
- Can intercept and modify network traffic between the distribution server and edge device
- Can attempt to serve a tampered or entirely malicious firmware binary
- Can attempt to replay an older, previously valid (but now vulnerable) signed firmware
  package to force a downgrade
- Cannot access the private signing key (held securely via environment variables /
  GitHub Secrets, never committed to source control)

**Out of scope:** compromise of the CI/CD pipeline itself, physical access to the edge
device, and side-channel attacks against the cryptographic implementation.

## Cryptographic Design

- **Key pair:** RSA-2048, generated via the `cryptography` library
- **Hashing:** SHA-256 over the full firmware binary, computed in chunks to support large files
- **Signing scheme:** RSA-PSS with MGF1(SHA-256) and maximum salt length — chosen over
  PKCS#1 v1.5 for its stronger security proof and resistance to certain forgery attacks
- **Verification:** the edge device holds only the public key and independently recomputes
  the SHA-256 hash of the downloaded firmware, then verifies the signature against that hash.
  Any mismatch (hash or signature) causes the update to be rejected and logged.
- **Anti-rollback (planned, Week 4):** firmware packages are versioned using a combination
  of timestamp and build iteration (see `firmware_metadata.py`); the edge device will track
  the last successfully installed version and refuse to install anything older.

## CI/CD Pipeline

Firmware is signed automatically via GitHub Actions whenever a version tag (`v*.*.*`) is
pushed. The pipeline:

1. Checks out the repository and installs dependencies
2. Verifies the `FIRMWARE_PRIVATE_KEY` secret is configured
3. Signs the firmware using the private key, injected securely as an environment variable
4. Re-verifies the signature as a sanity check
5. Runs the full unit test suite and tamper-detection integration test
6. Uploads the signed firmware, signature, and metadata as a downloadable artifact

The private key is never written to disk in plaintext outside the ephemeral CI runner
environment, and is never hardcoded anywhere in the repository.

## Project Structure
ota-secure-firmware-update/
├── .github/workflows/
│ └── sign-firmware.yml # CI/CD pipeline: signs firmware on release tags
├── keys/ # RSA key pair (gitignored — never committed)
├── firmware/
│ ├── dummy_firmware.bin # Sample firmware binary
│ ├── dummy_firmware.sig # RSA-PSS signature over its SHA-256 hash
│ └── dummy_firmware.meta.json # Version + build timestamp metadata
├── scripts/
│ ├── crypto_utils.py # Shared hashing / key-loading utilities
│ ├── generate_keys.py # Generates the RSA key pair
│ ├── sign_firmware.py # Hashes, signs, and writes metadata for firmware
│ ├── verify_firmware.py # Verifies a firmware signature
│ ├── firmware_metadata.py # Version metadata read/write helpers
│ ├── test_tamper_detection.py # End-to-end tamper detection integration test
│ └── test_signing_pipeline.py # Unit tests (isolated temp keys/firmware)
├── requirements.txt
└── README.md

## Setup

```powershell
python -m venv venv
venv\Scripts\Activate.ps1        # Windows PowerShell
pip install -r requirements.txt
```

## Usage

```powershell
# 1. Generate the signing key pair (one-time, or when rotating keys)
python scripts\generate_keys.py

# 2. Hash, sign, and version-tag a firmware binary (local key file)
python scripts\sign_firmware.py --version 1.0.0

# 3. Verify a signed firmware binary
python scripts\verify_firmware.py
```

## Testing

```powershell
# Unit tests (isolated — uses temp keys/firmware, never touches the real repo files)
python -m unittest scripts.test_signing_pipeline -v

# End-to-end tamper detection proof (corrupts real firmware, confirms rejection, restores it)
python scripts\test_tamper_detection.py
```

## Roadmap

- [x] Week 1: PKI setup, SHA-256 hashing, RSA-PSS signing, verification, tamper
      detection testing, shared crypto utilities, version metadata, unit tests
- [x] Week 2: GitHub Actions CI/CD pipeline — signs firmware automatically on
      release tags, verifies signature, runs full test suite, uploads signed
      artifact. Validated end-to-end via `v1.0.0` tag.
- [ ] Week 3: Simulated edge device verification agent
- [ ] Week 4: Anti-rollback / version control enforcement

## Security Notes

- Private keys are never committed to this repository (`keys/*.pem` is gitignored).
- The CI/CD pipeline injects the private key via GitHub Secrets as an environment
  variable, never written to disk in plaintext.
- All feature work is developed on isolated branches and merged via Pull Request;
  direct commits to `main` are avoided.