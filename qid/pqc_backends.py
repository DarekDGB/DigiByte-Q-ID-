"""
Optional PQC backend wiring for DigiByte Q-ID.

Guardrails:
- CI-safe by default: repo runs without oqs/liboqs installed.
- No silent fallback: if QID_PQC_BACKEND is selected for PQC algorithms,
  signing MUST fail-closed when backend isn't available.
- Verification MUST be fail-closed (return False to caller where appropriate).

Author: DarekDGB
License: MIT (see repo LICENSE)
"""

from __future__ import annotations

import os


class PQCBackendError(RuntimeError):
    """Raised when a real PQC backend is required but unavailable."""


# QID algorithm IDs
ML_DSA_ALGO = "pqc-ml-dsa"
FALCON_ALGO = "pqc-falcon"
HYBRID_ALGO = "pqc-hybrid-ml-dsa-falcon"

# liboqs algorithm names
_OQS_ALG_BY_QID = {
    ML_DSA_ALGO: "ML-DSA-44",
    FALCON_ALGO: "Falcon-512",
}


def selected_backend() -> str | None:
    v = os.getenv("QID_PQC_BACKEND", "").strip().lower()
    return v or None


def require_real_pqc() -> bool:
    """
    Backward-compatible helper for tests:
    True iff a PQC backend has been explicitly selected.
    """
    return selected_backend() is not None


def _oqs_alg_for(qid_alg: str) -> str:
    # Validate alg BEFORE importing oqs (tests expect ValueError for unsupported alg)
    if qid_alg not in (ML_DSA_ALGO, FALCON_ALGO):
        raise ValueError(f"Unsupported PQC alg: {qid_alg!r}")
    return _OQS_ALG_BY_QID[qid_alg]


def _import_oqs():
    """
    Import oqs (liboqs-python) lazily.

    Fail-closed:
    - If missing -> PQCBackendError
    - If import succeeds but module is not a usable oqs module -> PQCBackendError
      (important for tests that monkeypatch _import_oqs to return object()).
    """
    try:
        import oqs  # type: ignore
    except Exception as e:  # pragma: no cover
        raise PQCBackendError(
            "QID_PQC_BACKEND=liboqs selected but 'oqs' module is not available. "
            'Install optional deps: pip install -e ".[dev,pqc]"'
        ) from e

    # Ensure it looks like the expected liboqs-python module
    if not hasattr(oqs, "Signature"):
        raise PQCBackendError("Imported 'oqs' but it does not expose oqs.Signature (invalid backend)")

    return oqs


def enforce_no_silent_fallback_for_alg(alg: str) -> None:
    """
    If a real backend is selected, we must not silently use stub crypto for PQC algs.

    Raises PQCBackendError if:
    - backend is unknown
    - backend is selected but unavailable/misconfigured
    """
    backend = selected_backend()
    if backend is None:
        return

    if backend != "liboqs":
        raise PQCBackendError(f"Unknown QID_PQC_BACKEND: {backend!r}")

    if alg in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
        _import_oqs()
        return


def liboqs_sign(qid_alg: str, payload: bytes, private_key: bytes) -> bytes:
    """
    Real liboqs signing. Raises PQCBackendError if oqs is missing/misconfigured.
    """
    oqs_alg = _oqs_alg_for(qid_alg)
    oqs = _import_oqs()

    try:
        with oqs.Signature(oqs_alg, private_key) as signer:
            return signer.sign(payload)
    except TypeError as e:
        raise PQCBackendError(
            f"liboqs-python Signature({oqs_alg!r}, private_key) not supported on this platform"
        ) from e
    except Exception as e:
        raise PQCBackendError(f"liboqs sign failed for {oqs_alg!r}") from e


def liboqs_verify(qid_alg: str, payload: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Real liboqs verify.

    Raises PQCBackendError when oqs is missing/misconfigured.
    Callers that need "never raise" should catch and fail-closed.
    """
    oqs_alg = _oqs_alg_for(qid_alg)
    oqs = _import_oqs()

    try:
        with oqs.Signature(oqs_alg) as verifier:
            return bool(verifier.verify(payload, signature, public_key))
    except Exception:
        return False
