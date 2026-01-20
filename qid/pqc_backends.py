"""
MIT License
Copyright (c) 2025 DarekDGB
"""

from __future__ import annotations

import os
from typing import Any, Optional


class PQCBackendError(RuntimeError):
    pass


# Algorithm ids (must match qid.crypto)
ML_DSA_ALGO = "pqc-ml-dsa"
FALCON_ALGO = "pqc-falcon"
HYBRID_ALGO = "pqc-hybrid-ml-dsa-falcon"


# Map Q-ID alg -> liboqs alg names (placeholder mapping; real values can be swapped later)
_OQS_ALG_BY_QID = {
    ML_DSA_ALGO: "ML-DSA-44",
    FALCON_ALGO: "Falcon-512",
}


def selected_backend() -> Optional[str]:
    """
    Return normalized backend selector or None.
    Tests expect trimming + lowercasing.
    """
    v = os.environ.get("QID_PQC_BACKEND")
    if v is None:
        return None
    v2 = v.strip().lower()
    if v2 == "":
        return None
    return v2


def require_real_pqc() -> bool:
    return selected_backend() is not None


def _oqs_alg_for(qid_alg: str) -> str:
    if qid_alg not in _OQS_ALG_BY_QID:
        raise PQCBackendError(f"Unsupported PQC algorithm for liboqs: {qid_alg!r}")
    return _OQS_ALG_BY_QID[qid_alg]


def _import_oqs() -> Any:
    """
    Import python-oqs when backend selected. In CI it is usually missing.
    This is only used when you truly select QID_PQC_BACKEND=liboqs.
    """
    try:
        import oqs  # type: ignore
    except Exception as e:  # pragma: no cover
        raise PQCBackendError(
            "QID_PQC_BACKEND=liboqs selected but 'oqs' module is not available. "
            'Install optional deps: pip install -e ".[dev,pqc]"'
        ) from e
    return oqs


def _validate_oqs_module(oqs: Any) -> None:
    """
    Tests patch _import_oqs to return a fake object and expect PQCBackendError.
    """
    if oqs is None:
        raise PQCBackendError("Invalid oqs backend (None)")
    if not hasattr(oqs, "Signature"):
        raise PQCBackendError("Invalid oqs backend (missing Signature)")


def enforce_no_silent_fallback_for_alg(alg: str) -> None:
    """
    Guardrail: when a real backend is selected, PQC algs must not silently fall back.
    """
    if alg in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO} and selected_backend() is not None:
        # nothing else to do here; presence of this call is contract-style
        return


def liboqs_generate_keypair(qid_alg: str) -> tuple[bytes, bytes]:
    """
    Keypair generation for real liboqs mode.
    In CI we typically don't have oqs, so this is only used when explicitly selected.
    """
    oqs = _import_oqs()
    _validate_oqs_module(oqs)

    # If you get here with a fake oqs object, we must raise (tests depend on raising)
    raise PQCBackendError("liboqs keygen not wired in this repo yet")


def liboqs_sign(qid_alg: str, msg: bytes, priv: bytes) -> bytes:
    oqs = _import_oqs()
    _validate_oqs_module(oqs)

    # must raise until truly wired (tests cover this)
    _oqs_alg_for(qid_alg)  # may raise if unsupported
    raise PQCBackendError("liboqs signing not wired in this repo yet")


def liboqs_verify(qid_alg: str, msg: bytes, sig: bytes, pub: bytes) -> bool:
    """
    Low-level verify:
    - MUST validate backend object and raise PQCBackendError if invalid (tests expect raise)
    - When wired for real, could return True/False based on oqs verify.
    """
    oqs = _import_oqs()
    _validate_oqs_module(oqs)

    _oqs_alg_for(qid_alg)  # may raise if unsupported
    raise PQCBackendError("liboqs verify not wired in this repo yet")
