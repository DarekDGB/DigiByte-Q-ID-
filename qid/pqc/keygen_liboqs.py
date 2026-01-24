from __future__ import annotations

import os
from typing import Tuple

try:
    import oqs
except ImportError:  # pragma: no cover
    oqs = None


class PQCBackendError(RuntimeError):
    """Raised when a real PQC backend is required but unavailable."""


class PQCAlgorithmError(ValueError):
    """Raised when an unsupported PQC algorithm is requested."""


# Explicit allowlist — single source of truth
ALLOWED_ML_DSA_ALGS = {
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
}

ALLOWED_FALCON_ALGS = {
    "Falcon-512",
    "Falcon-1024",
}


def _require_liboqs() -> None:
    if os.environ.get("QID_PQC_BACKEND") != "liboqs":
        raise PQCBackendError("liboqs backend not enabled (QID_PQC_BACKEND!=liboqs)")
    if oqs is None:
        raise PQCBackendError("liboqs-python not installed")


def generate_ml_dsa_keypair(alg: str) -> Tuple[bytes, bytes]:
    # Fail-closed early on invalid algorithm (does not depend on backend availability)
    if alg not in ALLOWED_ML_DSA_ALGS:
        raise PQCAlgorithmError(f"ML-DSA algorithm not allowed: {alg}")

    _require_liboqs()

    with oqs.Signature(alg) as sig:
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
    return public_key, secret_key


def generate_falcon_keypair(alg: str) -> Tuple[bytes, bytes]:
    # Fail-closed early on invalid algorithm (does not depend on backend availability)
    if alg not in ALLOWED_FALCON_ALGS:
        raise PQCAlgorithmError(f"Falcon algorithm not allowed: {alg}")

    _require_liboqs()

    with oqs.Signature(alg) as sig:
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
    return public_key, secret_key
