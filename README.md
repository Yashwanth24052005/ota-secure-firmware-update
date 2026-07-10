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
- Cannot access the private signing key (assumed held securely via environment variables /
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
- **Anti-rollback:** firmware packages are versioned using a combination of timestamp and
  build iteration; the edge device tracks the last successfully installed version and
  refuses to install anything older.

## Project Structure

```
ota-secure-firmware-update/
├── keys/               # RSA key pair (gitignored — never committed)
├── firmware/           # Dummy firmware binary + generated signature
├── scripts/
│   ├── generate_keys.py    # Generates the RSA key pair
│   └── sign_firmware.py    # Hashes and signs the firmware binary
├── requirements.txt
└── README.md
```

## Setup

```bash
python -m venv venv
venv\Scripts\Activate.ps1        # Windows PowerShell
pip install -r requirements.txt
```

## Usage

```bash
# 1. Generate the signing key pair (one-time, or when rotating keys)
python scripts/generate_keys.py

# 2. Hash and sign a firmware binary
python scripts/sign_firmware.py
```

This produces a `.sig` file alongside the firmware binary, containing the RSA-PSS
signature over its SHA-256 hash.

## Roadmap

- [x] Week 1: PKI setup, SHA-256 hashing, RSA-PSS signing
- [ ] Week 2: GitHub Actions CI/CD pipeline for automated signing on release tags
- [ ] Week 3: Simulated edge device verification agent
- [ ] Week 4: Anti-rollback / version control mechanism

## Security Notes

- Private keys are never committed to this repository (`keys/*.pem` is gitignored).
- In the CI/CD pipeline (Week 2+), the private key is injected via GitHub Secrets as an
  environment variable and never written to disk in plaintext outside the runner's
  ephemeral environment.