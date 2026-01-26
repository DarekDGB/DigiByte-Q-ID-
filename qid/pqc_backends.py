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

from typing import Any, Iterable
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
oqs: Any = _OQS_UNSET  # tests may monkeypatch to None or a fake module


# Primary mapping used by tests via _oqs_alg_for().
# We also keep candidates via _oqs_alg_candidates_for() to support older liboqs names.
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


def _oqs_alg_for(qid_alg: str) -> str:
    """
    Convert Q-ID alg identifier to a primary liboqs algorithm name.

    IMPORTANT:
    - For non-PQC algs, this MUST raise ValueError (not PQCBackendError).
    """
    if qid_alg not in _OQS_ALG_BY_QID:
        raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")
    return _OQS_ALG_BY_QID[qid_alg]


def _oqs_alg_candidates_for(qid_alg: str) -> list[str]:
    """
    Return ordered list of liboqs algorithm names for this Q-ID alg.

    This allows compatibility across liboqs/python-oqs naming evolutions.
    """
    primary = _oqs_alg_for(qid_alg)
    if qid_alg == ML_DSA_ALGO:
        # Some stacks still expose Dilithium2 while newer stacks expose ML-DSA-44.
        # Try the primary first, then fallback candidates (still "real PQC", not a stub fallback).
        alts = ["Dilithium2"]
        return [primary, *[a for a in alts if a != primary]]
    return [primary]


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
    - if oqs is a cached module object -> MUST validate and return WITHOUT importing
    - if oqs hasn't been imported yet -> attempt import (so tests can monkeypatch __import__)
    - if import fails -> PQCBackendError (WITHOUT exception context for stability)
    """
    global oqs

    # Explicitly disabled by tests.
    if oqs is None:
        raise PQCBackendError(
            "QID_PQC_BACKEND=liboqs selected but 'oqs' module is not available."
        )

    # Cached already (tests may set oqs to a fake module).
    if oqs is not _OQS_UNSET:
        _validate_oqs_module(oqs)
        return oqs

    # First import attempt (must be real import statement so monkeypatched __import__ is hit).
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


# ---- Robust liboqs helpers (handle python-oqs API differences) ----


def _sig_ctx(mod: Any, alg: str, *, secret: bytes | None = None) -> Any:
    """
    Create a Signature object in the most compatible way we can.
    """
    Sig = getattr(mod, "Signature")
    # Try constructor with secret_key first.
    if secret is not None:
        try:
            return Sig(alg, secret_key=secret)  # type: ignore[arg-type]
        except TypeError:
            pass

    # Fall back to plain constructor.
    obj = Sig(alg)

    # Import secret key if supported.
    if secret is not None:
        imp = getattr(obj, "import_secret_key", None)
        if callable(imp):
            imp(secret)
        else:
            # Some variants may expose settable secret_key attr.
            try:
                setattr(obj, "secret_key", secret)
            except Exception:
                # We'll let sign() fail deterministically.
                pass

    return obj


def _try_sign_one(mod: Any, alg: str, msg: bytes, priv: bytes) -> bytes:
    obj = _sig_ctx(mod, alg, secret=priv)

    # Some versions are context managers; some are not.
    try:
        enter = getattr(obj, "__enter__", None)
        exit_ = getattr(obj, "__exit__", None)
        if callable(enter) and callable(exit_):
            with obj as s:
                out = s.sign(msg)
        else:
            out = obj.sign(msg)
    except TypeError:
        raise PQCBackendError("liboqs signing failed (Signature API mismatch)") from None
    except PQCBackendError:
        raise
    except Exception:
        raise PQCBackendError("liboqs signing failed") from None

    try:
        return bytes(out)
    except Exception:
        # If out is already bytes-like, bytes(out) works; otherwise fail closed.
        raise PQCBackendError("liboqs signing failed") from None


def _try_verify_one(mod: Any, alg: str, msg: bytes, sig: bytes, pub: bytes) -> bool:
    Sig = getattr(mod, "Signature")
    try:
        obj = Sig(alg)
    except TypeError:
        raise PQCBackendError("Invalid oqs backend object: Signature ctor failed") from None

    # Preferred: verify(sig, msg, pub) is common in python-oqs.
    verify = getattr(obj, "verify", None)
    if not callable(verify):
        raise PQCBackendError("Invalid oqs backend object: missing verify()") from None

    try:
        # Try common call orders.
        try:
            return bool(verify(sig, msg, pub))
        except TypeError:
            return bool(verify(msg, sig, pub))
    except (ValueError, PQCBackendError):
        raise
    except Exception:
        return False


def liboqs_sign(qid_alg: str, msg: bytes, priv: bytes) -> bytes:
    """
    Low-level sign using python-oqs.

    Contract:
    - Unsupported alg -> ValueError (before importing oqs)
    - Invalid oqs backend -> PQCBackendError
    - Any internal oqs failure -> PQCBackendError (stable message, no leaked context)
    """
    # Validate alg early (tests rely on ValueError before import).
    _ = _oqs_alg_for(qid_alg)

    mod = _import_oqs()
    _validate_oqs_module(mod)

    last_err: PQCBackendError | None = None
    for oqs_alg in _oqs_alg_candidates_for(qid_alg):
        try:
            return _try_sign_one(mod, oqs_alg, msg, priv)
        except PQCBackendError as e:
            last_err = e
            continue

    # Deterministic: raise a stable error (prefer the last PQCBackendError message).
    if last_err is not None:
        raise last_err
    raise PQCBackendError("liboqs signing failed") from None


def liboqs_verify(qid_alg: str, msg: bytes, sig: bytes, pub: bytes) -> bool:
    """
    Low-level verify using python-oqs.

    Contract:
    - Invalid backend object -> PQCBackendError (not swallowed)
    - Unsupported alg -> ValueError
    - Internal verifier error -> False (fail-closed)
    """
    _ = _oqs_alg_for(qid_alg)

    mod = _import_oqs()
    _validate_oqs_module(mod)

    # For verify we can try multiple alg names, but must fail-closed on internal issues.
    for oqs_alg in _oqs_alg_candidates_for(qid_alg):
        try:
            ok = _try_verify_one(mod, oqs_alg, msg, sig, pub)
        except (ValueError, PQCBackendError):
            raise
        except Exception:
            return False
        if ok:
            return True
    return False
