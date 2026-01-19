"""
Optional PQC backend wiring for DigiByte Q-ID.

This module is intentionally:
- import-safe (does not require liboqs-python unless selected)
- fail-closed (no silent fallback)
- minimal scaffolding (real wiring comes next)

Backend selection is controlled by env var:
  QID_PQC_BACKEND=liboqs

If not set, Q-ID continues using the deterministic stub signing in qid.crypto
(so CI remains green).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from qid.crypto import FALCON_ALGO, HYBRID_ALGO, ML_DSA_ALGO


class PQCBackendError(RuntimeError):
    """Raised when a real PQC backend is required but unavailable."""


def selected_backend() -> Optional[str]:
    v = os.getenv("QID_PQC_BACKEND", "").strip().lower()
    return v or None


def require_real_pqc() -> bool:
    return selected_backend() is not None


def _import_oqs():
    # liboqs-python exposes the module name `oqs` in many installations.
    # If it isn't available, we fail closed when the backend is selected.
    try:
        import oqs  # type: ignore
    except Exception as e:  # pragma: no cover
        raise PQCBackendError(
            "QID_PQC_BACKEND=liboqs selected but 'oqs' module is not available. "
            "Install optional deps: pip install -e \".[dev,pqc]\""
        ) from e
    return oqs


@dataclass(frozen=True)
class PQCSignatureResult:
    alg: str
    signature: bytes


def liboqs_sign(alg: str, payload: bytes, private_key: bytes) -> bytes:
    """
    Placeholder surface for real liboqs signing.

    We don't implement the signing logic here yet — this is scaffolding.
    Next step will define key formats + actual oqs.Signature(...) usage.
    """
    if alg not in {ML_DSA_ALGO, FALCON_ALGO}:
        raise ValueError(f"Unsupported PQC alg: {alg}")

    _ = _import_oqs()
    raise PQCBackendError(
        "liboqs backend selected but real signing is not wired yet "
        "(scaffolding step complete; wiring step next)."
    )


def liboqs_verify(alg: str, payload: bytes, signature: bytes, public_key: bytes) -> bool:
    if alg not in {ML_DSA_ALGO, FALCON_ALGO}:
        raise ValueError(f"Unsupported PQC alg: {alg}")

    _ = _import_oqs()
    raise PQCBackendError(
        "liboqs backend selected but real verification is not wired yet "
        "(scaffolding step complete; wiring step next)."
    )


def enforce_no_silent_fallback_for_alg(alg: str) -> None:
    """
    Guardrail: if user explicitly selects a real PQC backend, we must not
    proceed with stubs for PQC algorithms.
    """
    backend = selected_backend()
    if backend is None:
        return

    if backend != "liboqs":
        raise PQCBackendError(f"Unknown QID_PQC_BACKEND: {backend!r}")

    # Only enforce for PQC algorithms; DEV remains dev-only.
    if alg in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
        # backend is selected, therefore "real PQC required"
        # wiring happens in the next step; for now, fail closed.
        raise PQCBackendError(
            f"Real PQC backend selected ({backend}) for alg={alg}, "
            "but real PQC wiring is not enabled yet."
        )
