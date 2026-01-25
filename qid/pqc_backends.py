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


class _OQSUnset:
    pass


_OQS_UNSET = _OQSUnset()
oqs: Any = _OQS_UNSET  # tests may monkeypatch to None


# Prefer modern NIST names, but support legacy Dilithium naming via fallback.
_OQS_ALG_BY_QID = {
    ML_DSA_ALGO: "ML-DSA-44",
    FALCON_ALGO: "Falcon-512",
}


def selected_backend() -> str | None:
    raw = os.getenv("QID_PQC_BACKEND")
    if raw is None:
        return None
    s = raw.strip().lower()
    return s or None


def require_real_pqc() -> bool:
    return selected_backend() is not None

def _oqs_alg_for(qid_alg: str) -> str:
    """
    Back-compat shim for tests that expect _oqs_alg_for().

    Returns the *primary* liboqs algorithm name for a Q-ID alg.
    Raises ValueError for unsupported algs (as tests require).
    """
    candidates = _oqs_alg_candidates_for(qid_alg)
    return candidates[0]


def _oqs_alg_candidates_for(qid_alg: str) -> tuple[str, ...]:
    if qid_alg not in _OQS_ALG_BY_QID:
        raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")

    primary = _OQS_ALG_BY_QID[qid_alg]

    if qid_alg == ML_DSA_ALGO:
        return (primary, "Dilithium2")

    return (primary,)


def _validate_oqs_module(mod: Any) -> None:
    sig = getattr(mod, "Signature", None)
    if sig is None or not callable(sig):
        raise PQCBackendError("Invalid oqs backend object: missing callable Signature")


def _import_oqs() -> Any:
    global oqs

    if oqs is None:
        raise PQCBackendError(
            "QID_PQC_BACKEND=liboqs selected but 'oqs' module is not available."
        )

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

    if qid_alg not in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
        return

    mod = _import_oqs()
    _validate_oqs_module(mod)


def liboqs_sign(qid_alg: str, msg: bytes, priv: bytes) -> bytes:
    candidates = _oqs_alg_candidates_for(qid_alg)  # may raise ValueError
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
            raise PQCBackendError("liboqs signing failed (Signature API mismatch)") from None
        except PQCBackendError:
            raise
        except Exception:
            continue

    raise PQCBackendError("liboqs signing failed") from None


def liboqs_verify(qid_alg: str, msg: bytes, sig: bytes, pub: bytes) -> bool:
    candidates = _oqs_alg_candidates_for(qid_alg)  # may raise ValueError
    mod = _import_oqs()
    _validate_oqs_module(mod)

    for oqs_alg in candidates:
        try:
            if qid_alg == ML_DSA_ALGO:
                from qid.pqc.pqc_ml_dsa import verify_ml_dsa

                return bool(
                    verify_ml_dsa(oqs=mod, msg=msg, sig=sig, pub=pub, oqs_alg=oqs_alg)
                )

            if qid_alg == FALCON_ALGO:
                from qid.pqc.pqc_falcon import verify_falcon

                return bool(
                    verify_falcon(oqs=mod, msg=msg, sig=sig, pub=pub, oqs_alg=oqs_alg)
                )

            raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")

        except (ValueError, PQCBackendError):
            raise
        except Exception:
            continue

    return False
