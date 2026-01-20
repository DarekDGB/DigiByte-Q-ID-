"""
Optional PQC backend wiring for DigiByte Q-ID.

Guardrails:
- CI-safe by default: repo runs without oqs/liboqs installed.
- No silent fallback: if QID_PQC_BACKEND is selected for PQC algorithms,
  signing MUST fail-closed when backend isn't available.
- Verification may be used in two modes:
  - "raise" mode (this module): raise PQCBackendError if backend is missing/invalid
  - "fail-closed boolean" mode (caller): catch PQCBackendError and return False

Author: DarekDGB
License: MIT (see repo LICENSE)
"""

from __future__ import annotations

import os
from typing import Any, Optional, Tuple


class PQCBackendError(RuntimeError):
    """Raised when a real PQC backend is required but unavailable."""


# QID algorithm IDs
ML_DSA_ALGO = "pqc-ml-dsa"
FALCON_ALGO = "pqc-falcon"
HYBRID_ALGO = "pqc-hybrid-ml-dsa-falcon"

# liboqs algorithm names (stable mapping)
_OQS_ALG_BY_QID = {
    ML_DSA_ALGO: "ML-DSA-44",
    FALCON_ALGO: "Falcon-512",
}


def selected_backend() -> Optional[str]:
    """
    Return selected PQC backend identifier, or None if unset.

    Allowed:
      - None (default stub mode)
      - "liboqs"
    """
    v = os.getenv("QID_PQC_BACKEND")
    if v is None or v == "":
        return None
    return v


def _oqs_alg_for(qid_alg: str) -> str:
    if qid_alg not in _OQS_ALG_BY_QID:
        raise PQCBackendError(f"Unsupported PQC algorithm for liboqs: {qid_alg!r}")
    return _OQS_ALG_BY_QID[qid_alg]


def _validate_oqs_module(oqs: Any) -> None:
    # Guard against tests monkeypatching _import_oqs to return a dummy object.
    if not hasattr(oqs, "Signature"):
        raise PQCBackendError("oqs module missing Signature class (invalid oqs import)")


def _import_oqs() -> Any:
    try:
        import oqs  # type: ignore
        _validate_oqs_module(oqs)
        return oqs
    except Exception as e:
        raise PQCBackendError(
            "QID_PQC_BACKEND=liboqs selected but 'oqs' module is not available. "
            'Install optional deps: pip install -e ".[dev,pqc]"'
        ) from e


def enforce_no_silent_fallback_for_alg(alg: str) -> None:
    """
    If a real backend is selected, we must not silently use stub crypto for PQC algs.

    Raises PQCBackendError if:
    - backend is unknown
    - backend required for this algorithm but not available
    """
    backend = selected_backend()
    if backend is None:
        return

    if backend != "liboqs":
        raise PQCBackendError(f"Unknown QID_PQC_BACKEND value: {backend!r}")

    if alg in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
        # Ensure oqs is importable and sane
        _import_oqs()


def liboqs_generate_keypair(qid_alg: str) -> Tuple[bytes, bytes]:
    """
    Generate (public_key, secret_key) for a single PQC algorithm using liboqs-python.

    Raises PQCBackendError if oqs is missing/misconfigured or API is unsupported.
    """
    oqs_alg = _oqs_alg_for(qid_alg)
    oqs = _import_oqs()

    # NOTE: liboqs-python API may differ by platform/version.
    # We try the common pattern and fail loudly if unsupported.
    try:
        with oqs.Signature(oqs_alg) as s:
            pub = s.generate_keypair()
            # export_secret_key() is the common way to obtain private key bytes
            sec = s.export_secret_key()
            if not isinstance(pub, (bytes, bytearray)) or not isinstance(sec, (bytes, bytearray)):
                raise PQCBackendError("oqs keypair generation returned non-bytes")
            return bytes(pub), bytes(sec)
    except AttributeError as e:
        raise PQCBackendError(
            f"liboqs-python API missing generate_keypair/export_secret_key for {oqs_alg!r}"
        ) from e
    except TypeError as e:
        raise PQCBackendError(
            f"liboqs-python Signature({oqs_alg!r}) not supported on this platform"
        ) from e
    except Exception as e:
        raise PQCBackendError(f"liboqs keygen failed for {oqs_alg!r}") from e


def liboqs_sign(qid_alg: str, payload: bytes, private_key: bytes) -> bytes:
    """
    Real liboqs signing. Raises PQCBackendError if oqs is missing/misconfigured.
    """
    oqs_alg = _oqs_alg_for(qid_alg)
    oqs = _import_oqs()

    try:
        with oqs.Signature(oqs_alg, private_key) as signer:
            sig = signer.sign(payload)
            if not isinstance(sig, (bytes, bytearray)):
                raise PQCBackendError("oqs sign returned non-bytes")
            return bytes(sig)
    except TypeError as e:
        raise PQCBackendError(
            f"liboqs-python Signature({oqs_alg!r}, private_key) not supported on this platform"
        ) from e
    except Exception as e:
        raise PQCBackendError(f"liboqs sign failed for {oqs_alg!r}") from e


def liboqs_verify(qid_alg: str, payload: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Real liboqs verification.
    Returns boolean and never raises for signature mismatch, but may raise PQCBackendError
    for missing/misconfigured backend.
    """
    oqs_alg = _oqs_alg_for(qid_alg)
    oqs = _import_oqs()

    try:
        with oqs.Signature(oqs_alg) as verifier:
            return bool(verifier.verify(payload, signature, public_key))
    except Exception:
        return False
