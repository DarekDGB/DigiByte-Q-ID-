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

from typing import Any
import os


# These constants are also imported by tests.
ML_DSA_ALGO = "pqc-ml-dsa"
FALCON_ALGO = "pqc-falcon"
HYBRID_ALGO = "pqc-hybrid-ml-dsa-falcon"


class PQCBackendError(RuntimeError):
    pass


# We need three states for determinism in tests:
# - UNSET: we have not attempted import yet (normal runtime)
# - None: tests (or callers) explicitly disabled oqs by monkeypatching pb.oqs = None
# - module: cached imported module
class _OQSUnset:
    pass


_OQS_UNSET = _OQSUnset()
oqs: Any = _OQS_UNSET  # tests may monkeypatch to None


# Map Q-ID alg identifiers to liboqs algorithm names.
_OQS_ALG_BY_QID = {
    ML_DSA_ALGO: "Dilithium2",  # ML-DSA-44 maps to Dilithium2 in liboqs naming
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


def _oqs_alg_for(qid_alg: str) -> str:
    """
    Convert Q-ID alg identifier to liboqs algorithm name.

    IMPORTANT:
    - For non-PQC algs, this MUST raise ValueError (not PQCBackendError).
    """
    if qid_alg not in _OQS_ALG_BY_QID:
        raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")
    return _OQS_ALG_BY_QID[qid_alg]


def _validate_oqs_module(mod: Any) -> None:
    """
    Validate that `mod` looks like python-oqs.

    Tests expect PQCBackendError when invalid.
    """
    sig = getattr(mod, "Signature", None)
    if sig is None or not callable(sig):
        raise PQCBackendError("Invalid oqs backend object: missing callable Signature")


def _import_oqs() -> Any:
    """
    Import python-oqs when backend selected.

    Determinism contract for tests:
    - if tests monkeypatch `qid.pqc_backends.oqs = None` -> MUST raise PQCBackendError
    - if oqs hasn't been imported yet -> attempt import (so tests can monkeypatch __import__)
    - if import fails -> PQCBackendError
    """
    global oqs

    # Explicitly disabled by tests.
    if oqs is None:
        raise PQCBackendError(
            "QID_PQC_BACKEND=liboqs selected but 'oqs' module is not available."
        )

    # Cached already.
    if oqs is not _OQS_UNSET:
        return oqs

    # First import attempt.
    try:
        import oqs as mod  # type: ignore
    except Exception as e:  # pragma: no cover
        raise PQCBackendError(
            "QID_PQC_BACKEND=liboqs selected but 'oqs' module is not available. "
            'Install optional deps: pip install -e ".[dev,pqc]"'
        ) from e

    oqs = mod
    return mod


def enforce_no_silent_fallback_for_alg(qid_alg: str) -> None:
    """
    Guardrail: if a real backend is selected, PQC algorithms must NOT silently fall back.

    Behavior:
    - unknown backend -> PQCBackendError
    - liboqs selected but oqs missing -> PQCBackendError for PQC algs
    - backend not selected -> no-op
    """
    backend = selected_backend()
    if backend is None:
        return

    if backend != "liboqs":
        raise PQCBackendError(f"Unknown QID_PQC_BACKEND: {backend!r}")

    if qid_alg not in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
        return

    mod = _import_oqs()
    _validate_oqs_module(mod)


def liboqs_sign(qid_alg: str, msg: bytes, priv: bytes) -> bytes:
    """
    Low-level sign using python-oqs.

    Contract:
    - Unsupported alg -> ValueError (before importing oqs)
    - Invalid oqs backend -> PQCBackendError
    - TypeError in oqs flow -> PQCBackendError (stable message)
    """
    oqs_alg = _oqs_alg_for(qid_alg)  # may raise ValueError
    mod = _import_oqs()
    _validate_oqs_module(mod)

    try:
        if qid_alg == ML_DSA_ALGO:
            from qid.pqc.pqc_ml_dsa import sign_ml_dsa

            return sign_ml_dsa(oqs=mod, msg=msg, priv=priv, oqs_alg=oqs_alg)

        if qid_alg == FALCON_ALGO:
            from qid.pqc.pqc_falcon import sign_falcon

            return sign_falcon(oqs=mod, msg=msg, priv=priv, oqs_alg=oqs_alg)

        # Hybrid is composed at a higher layer (strict AND)
        raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")

    except TypeError as e:
        raise PQCBackendError("liboqs signing failed (Signature ctor rejected inputs)") from e
    except PQCBackendError:
        raise
    except Exception as e:  # pragma: no cover
        raise PQCBackendError("liboqs signing failed") from e


def liboqs_verify(qid_alg: str, msg: bytes, sig: bytes, pub: bytes) -> bool:
    """
    Low-level verify using python-oqs.

    Contract:
    - Invalid backend object -> PQCBackendError (not swallowed)
    - Unsupported alg -> ValueError
    - Internal verifier error -> False (fail-closed)
    """
    oqs_alg = _oqs_alg_for(qid_alg)  # may raise ValueError
    mod = _import_oqs()
    _validate_oqs_module(mod)

    try:
        if qid_alg == ML_DSA_ALGO:
            from qid.pqc.pqc_ml_dsa import verify_ml_dsa

            return bool(verify_ml_dsa(oqs=mod, msg=msg, sig=sig, pub=pub, oqs_alg=oqs_alg))

        if qid_alg == FALCON_ALGO:
            from qid.pqc.pqc_falcon import verify_falcon

            return bool(verify_falcon(oqs=mod, msg=msg, sig=sig, pub=pub, oqs_alg=oqs_alg))

        raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")

    except (ValueError, PQCBackendError):
        raise
    except Exception:
        return False
