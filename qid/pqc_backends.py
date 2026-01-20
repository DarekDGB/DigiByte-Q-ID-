"""
Optional PQC backend wiring for DigiByte Q-ID.

Design intent (matches tests):
- CI-safe by default: repo runs without oqs installed.
- Selecting QID_PQC_BACKEND enforces "no silent fallback" at SIGN/VERIFY time.
- Key generation remains CI-safe and does NOT require oqs unless explicitly called.
- selected_backend() must normalize and trim.
- require_real_pqc() must exist.

Author: DarekDGB
License: MIT (see repo LICENSE)
"""

from __future__ import annotations

import os
from typing import Any, Optional, Tuple


class PQCBackendError(RuntimeError):
    """Raised when a real PQC backend is required but unavailable or invalid."""


# Q-ID algorithm IDs (must match qid.crypto)
ML_DSA_ALGO = "pqc-ml-dsa"
FALCON_ALGO = "pqc-falcon"
HYBRID_ALGO = "pqc-hybrid-ml-dsa-falcon"

# Mapping from Q-ID alg IDs to liboqs alg names.
_OQS_ALG_BY_QID = {
    ML_DSA_ALGO: "ML-DSA-44",
    FALCON_ALGO: "Falcon-512",
}


def selected_backend() -> Optional[str]:
    """
    Return selected PQC backend identifier, or None if unset.

    Normalization rules (tests rely on these):
    - strip whitespace
    - lowercase
    - empty => None
    """
    v = os.getenv("QID_PQC_BACKEND")
    if v is None:
        return None
    v2 = v.strip().lower()
    if v2 == "":
        return None
    return v2


def require_real_pqc() -> bool:
    """True if a backend is selected (tests expect this helper)."""
    return selected_backend() is not None


def _oqs_alg_for(qid_alg: str) -> str:
    # Tests expect ValueError for unsupported alg in liboqs_sign/verify.
    if qid_alg not in _OQS_ALG_BY_QID:
        raise ValueError(f"Unsupported PQC algorithm for liboqs: {qid_alg!r}")
    return _OQS_ALG_BY_QID[qid_alg]


def _validate_oqs_module(oqs: Any) -> None:
    if not hasattr(oqs, "Signature"):
        raise PQCBackendError("oqs module missing Signature class (invalid oqs import)")


def _import_oqs() -> Any:
    try:
        import oqs  # type: ignore
    except Exception as e:  # pragma: no cover
        raise PQCBackendError(
            "QID_PQC_BACKEND=liboqs selected but 'oqs' module is not available. "
            'Install optional deps: pip install -e ".[dev,pqc]"'
        ) from e

    _validate_oqs_module(oqs)
    return oqs


def enforce_no_silent_fallback_for_alg(alg: str) -> None:
    """
    If a real backend is selected, we must not silently use stub crypto for PQC algs.

    This is enforced at SIGN/VERIFY time (tests rely on this).
    """
    backend = selected_backend()
    if backend is None:
        return

    if backend != "liboqs":
        raise PQCBackendError(f"Unknown QID_PQC_BACKEND value: {backend!r}")

    if alg in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
        _import_oqs()


def liboqs_generate_keypair(qid_alg: str) -> Tuple[bytes, bytes]:
    """
    OPTIONAL helper: real keygen for PQC algorithms using liboqs-python.

    IMPORTANT: This is NOT called by default CI-safe keygen.
    It is used only in opt-in environments/tests.
    """
    oqs_alg = _oqs_alg_for(qid_alg)
    oqs = _import_oqs()

    try:
        with oqs.Signature(oqs_alg) as s:
            pub = s.generate_keypair()
            sec = s.export_secret_key()
            if not isinstance(pub, (bytes, bytearray)) or not isinstance(sec, (bytes, bytearray)):
                raise PQCBackendError("oqs keypair generation returned non-bytes")
            return bytes(pub), bytes(sec)
    except AttributeError as e:
        raise PQCBackendError(
            f"liboqs-python API missing generate_keypair/export_secret_key for {oqs_alg!r}"
        ) from e
    except Exception as e:
        raise PQCBackendError(f"liboqs keygen failed for {oqs_alg!r}") from e


def liboqs_sign(qid_alg: str, payload: bytes, private_key: bytes) -> bytes:
    """
    Real liboqs signing.

    Unsupported alg => ValueError (tests expect this).
    Missing backend => PQCBackendError.
    """
    oqs_alg = _oqs_alg_for(qid_alg)
    oqs = _import_oqs()

    try:
        with oqs.Signature(oqs_alg, private_key) as signer:
            sig = signer.sign(payload)
            if not isinstance(sig, (bytes, bytearray)):
                raise PQCBackendError("oqs sign returned non-bytes")
            return bytes(sig)
    except Exception as e:
        raise PQCBackendError(f"liboqs sign failed for {oqs_alg!r}") from e


def liboqs_verify(qid_alg: str, payload: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Real liboqs verification.

    Unsupported alg => ValueError (tests expect this).
    Missing backend => PQCBackendError.
    Signature mismatch => False.
    """
    oqs_alg = _oqs_alg_for(qid_alg)
    oqs = _import_oqs()

    try:
        with oqs.Signature(oqs_alg) as verifier:
            return bool(verifier.verify(payload, signature, public_key))
    except Exception:
        return False
