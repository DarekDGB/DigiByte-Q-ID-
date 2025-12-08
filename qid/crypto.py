"""
Crypto helpers for DigiByte Q-ID.

This module provides a **development-only** cryptographic layer for Q-ID.

It is intentionally simple and self-contained so it can run everywhere
(including GitHub Actions and an iPhone-only workflow) while exposing the
same interfaces that a future PQC implementation will use.

Production deployments are expected to replace the internals with real
post-quantum / hybrid algorithms, keeping function signatures stable.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Dict, Any


# ---------------------------------------------------------------------------
# Algorithms
# ---------------------------------------------------------------------------

# Development algorithm name. In the future we expect names like:
# - "pqc-ml-dsa"
# - "hybrid-ecdsa-ml-dsa"
DEV_ALGO = "dev-hmac-sha256"


@dataclass
class QIDKeyPair:
    """
    Minimal keypair structure for the dev crypto backend.

    In this dev implementation we use a symmetric secret key with HMAC-SHA256.
    The "public_key" is derived from the secret key for identification only.
    This is NOT a real public-key scheme – it is a placeholder.
    """
    algorithm: str
    secret_key: str  # base64-encoded bytes
    public_key: str  # base64-encoded bytes


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _canonical_json(data: Dict[str, Any]) -> bytes:
    """
    Serialize a payload into canonical JSON bytes.

    - Keys sorted
    - No extra whitespace
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_dev_keypair() -> QIDKeyPair:
    """
    Generate a development-only Q-ID keypair.

    - 32-byte secret key (random)
    - public key = SHA256(secret_key)

    In real PQC deployments this function will be replaced with calls to a
    proper keygen routine for ML-DSA / hybrid schemes.
    """
    secret = secrets.token_bytes(32)
    pub = hashlib.sha256(secret).digest()
    return QIDKeyPair(
        algorithm=DEV_ALGO,
        secret_key=_b64encode(secret),
        public_key=_b64encode(pub),
    )


def sign_payload(payload: Dict[str, Any], keypair: QIDKeyPair) -> str:
    """
    Sign a payload with the given keypair.

    For the dev backend we use HMAC-SHA256(secret_key, canonical_json(payload)).
    The result is base64-encoded.

    This is NOT a real public-key signature – it is deterministic,
    tamper-evident, and sufficient for tests and local development.
    """
    if keypair.algorithm != DEV_ALGO:
        raise ValueError(f"Unsupported algorithm: {keypair.algorithm}")

    msg = _canonical_json(payload)
    secret = _b64decode(keypair.secret_key)
    sig = hmac.new(secret, msg, hashlib.sha256).digest()
    return _b64encode(sig)


def verify_payload(payload: Dict[str, Any], signature: str, keypair: QIDKeyPair) -> bool:
    """
    Verify a signature over a payload using the given keypair.

    In a real public-key scheme we would use only the public key here.
    For the dev backend we re-run HMAC with the same secret and compare.
    """
    if keypair.algorithm != DEV_ALGO:
        raise ValueError(f"Unsupported algorithm: {keypair.algorithm}")

    msg = _canonical_json(payload)
    secret = _b64decode(keypair.secret_key)
    expected = hmac.new(secret, msg, hashlib.sha256).digest()
    try:
        given = _b64decode(signature)
    except Exception:
        return False
    return hmac.compare_digest(expected, given)
