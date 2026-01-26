"""
PQC backend selection + wiring for DigiByte Q-ID.

Design goals (contract + tests):
- CI-safe by default: no pqc deps required unless user explicitly selects a backend.
- No silent fallback: if a real backend is selected, PQC algs MUST NOT silently degrade.
- Deterministic behavior:
  - sign paths may raise PQCBackendError when backend selected but unavailable.
  - verify paths MUST fail-closed (return False) on internal errors.
"""

from __future__ import annotations

import os
from typing import Any


# These constants are also imported by tests.
ML_DSA_ALGO = "pqc-ml-dsa"
FALCON_ALGO = "pqc-falcon"
HYBRID_ALGO = "pqc-hybrid-ml-dsa-falcon"


class PQCBackendError(RuntimeError):
    pass


class _OQSUnset:
    pass


_OQS_UNSET = _OQSUnset()

# Tests may monkeypatch this to:
# - None (meaning: explicitly unavailable)
# - a module-like object (meaning: "cached oqs module", avoid importing real optional dep)
oqs: Any = _OQS_UNSET


# Prefer modern NIST names, but support legacy Dilithium naming via fallback.
_OQS_ALG_BY_QID = {
    ML_DSA_ALGO: "ML-DSA-44",
    FALCON_ALGO: "Falcon-512",
}


def selected_backend() -> str | None:
    """
    Return normalized selected backend from env var QID_PQC_BACKEND.

    - None means "stub mode" (CI-safe).
    - "liboqs" means "real PQC backend expected".
    """
    raw = os.getenv("QID_PQC_BACKEND")
    if raw is None:
        return None
    s = raw.strip().lower()
    return s or None


def require_real_pqc() -> bool:
    """True when user explicitly selected a real PQC backend."""
    return selected_backend() is not None


def _oqs_alg_candidates_for(qid_alg: str) -> tuple[str, ...]:
    """
    Return candidate liboqs algorithm names for a given Q-ID alg.

    Must raise ValueError for unsupported algs (tests rely on this),
    and must list modern name first.
    """
    if qid_alg not in _OQS_ALG_BY_QID:
        raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")

    primary = _OQS_ALG_BY_QID[qid_alg]

    if qid_alg == ML_DSA_ALGO:
        # Back-compat: older python-oqs/liboqs stacks used Dilithium2 naming.
        return (primary, "Dilithium2")

    return (primary,)


def _oqs_alg_for(qid_alg: str) -> str:
    """
    Back-compat shim for tests that expect _oqs_alg_for().

    Returns the *primary* liboqs algorithm name for a Q-ID alg.
    Raises ValueError for unsupported algs (as tests require).
    """
    return _oqs_alg_candidates_for(qid_alg)[0]


def _validate_oqs_module(mod: Any) -> None:
    sig = getattr(mod, "Signature", None)
    if sig is None or not callable(sig):
        raise PQCBackendError("Invalid oqs backend object: missing callable Signature")


def _import_oqs() -> Any:
    """
    Import (or return cached) oqs module.

    Critical test contracts:
    - If tests inject a cached module-like object into `qid.pqc_backends.oqs`
      AND backend is selected as liboqs, we must use that and NOT import.
    - If oqs is None, treat as unavailable and raise PQCBackendError.
    - If oqs is unset, attempt real import (may fail and raise PQCBackendError).
    """
    global oqs

    backend = selected_backend()

    # Explicit "unavailable" knob (tests may set oqs=None)
    if oqs is None:
        raise PQCBackendError("QID_PQC_BACKEND=liboqs selected but 'oqs' module is not available.")

    # If user selected liboqs AND tests (or embedder) injected a cached module-like
    # object, use it and do not import the real optional dep.
    if backend == "liboqs" and oqs is not _OQS_UNSET:
        _validate_oqs_module(oqs)
        return oqs

    try:
        import oqs as mod  # type: ignore
    except Exception:
        raise PQCBackendError(
            "QID_PQC_BACKEND=liboqs selected but 'oqs' module is not available. "
            'Install optional deps: pip install -e ".[dev,pqc]"'
        ) from None

    _validate_oqs_module(mod)
    oqs = mod
    return mod


def enforce_no_silent_fallback_for_alg(qid_alg: str) -> None:
    backend = selected_backend()
    if backend is None:
        return

    if backend != "liboqs":
        raise PQCBackendError(f"Unknown QID_PQC_BACKEND: {backend!r}")

    # Allow non-PQC algs even when backend selected (tests require dev algo no-op).
    if qid_alg not in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
        return

    mod = _import_oqs()
    _validate_oqs_module(mod)


def liboqs_sign(qid_alg: str, msg: bytes, priv: bytes) -> bytes:
    # MUST raise ValueError for unsupported alg BEFORE importing oqs (tests rely on this).
    candidates = _oqs_alg_candidates_for(qid_alg)

    mod = _import_oqs()
    _validate_oqs_module(mod)

    for oqs_alg in candidates:
        try:
            if qid_alg == ML_DSA_ALGO:
                from qid.pqc.pqc_ml_dsa import sign_ml_dsa

                return sign_ml_dsa(oqs=mod, msg=msg, priv=priv, oqs_alg=oqs_alg)

            if qid_alg == FALCON_ALGO:
                from qid.pqc.pqc_falcon import sign_falcon

                return sign_falcon(oqs=mod, msg=msg, priv=priv, oqs_alg=oqs_alg)

            raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")

        except TypeError:
            # Deterministic error for API mismatches.
            raise PQCBackendError("liboqs signing failed (Signature API mismatch)") from None
        except PQCBackendError:
            raise
        except Exception:
            # Try next candidate (e.g., ML-DSA-44 then Dilithium2).
            continue

    raise PQCBackendError("liboqs signing failed") from None


def liboqs_verify(qid_alg: str, msg: bytes, sig: bytes, pub: bytes) -> bool:
    """
    Verify must be fail-closed.

    Critical test contract:
    - MUST raise ValueError for unsupported alg BEFORE importing oqs.
    """
    candidates = _oqs_alg_candidates_for(qid_alg)

    try:
        mod = _import_oqs()
        _validate_oqs_module(mod)
    except PQCBackendError:
        return False
    except Exception:
        return False

    for oqs_alg in candidates:
        try:
            if qid_alg == ML_DSA_ALGO:
                from qid.pqc.pqc_ml_dsa import verify_ml_dsa

                return bool(verify_ml_dsa(oqs=mod, msg=msg, sig=sig, pub=pub, oqs_alg=oqs_alg))

            if qid_alg == FALCON_ALGO:
                from qid.pqc.pqc_falcon import verify_falcon

                return bool(verify_falcon(oqs=mod, msg=msg, sig=sig, pub=pub, oqs_alg=oqs_alg))

            raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")

        except ValueError:
            # Unsupported algorithm must propagate (contract).
            raise
        except Exception:
            # Try next candidate or fail closed.
            continue

    return False
