"""
Optional PQC backend wiring for DigiByte Q-ID.

Design goals:
- import-safe (does not require liboqs-python unless selected)
- fail-closed (no silent fallback)
- CI-safe by default (stub backend remains default)
- real signing/verifying available when QID_PQC_BACKEND=liboqs

Backend selection:
  QID_PQC_BACKEND=liboqs

Author: DarekDGB
License: MIT (see repo LICENSE.md)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from qid.crypto import FALCON_ALGO, HYBRID_ALGO, ML_DSA_ALGO


class PQCBackendError(RuntimeError):
    """Raised when a real PQC backend is required but unavailable."""


# OQS algorithm names (liboqs identifiers)
# ML-DSA-44 and Falcon-512 are defined by liboqs.  [oai_citation:4‡GitHub](https://github.com/open-quantum-safe/liboqs/blob/master/src/sig/sig.h?utm_source=chatgpt.com)
_OQS_ALG_BY_QID = {
    ML_DSA_ALGO: "ML-DSA-44",
    FALCON_ALGO: "Falcon-512",
}


def selected_backend() -> Optional[str]:
    v = os.getenv("QID_PQC_BACKEND", "").strip().lower()
    return v or None


def require_real_pqc() -> bool:
    return selected_backend() is not None


def _import_oqs():
    """
    Import oqs (from liboqs-python) lazily.
    If unavailable and backend selected, fail closed.
    """
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


def _oqs_alg_for(qid_alg: str) -> str:
    if qid_alg not in (ML_DSA_ALGO, FALCON_ALGO):
        raise ValueError(f"Unsupported PQC alg: {qid_alg}")
    return _OQS_ALG_BY_QID[qid_alg]


def liboqs_generate_keypair(qid_alg: str) -> tuple[bytes, bytes]:
    """
    Returns (public_key_bytes, secret_key_bytes) for the given Q-ID PQC algorithm.
    """
    oqs = _import_oqs()
    oqs_alg = _oqs_alg_for(qid_alg)

    try:
        with oqs.Signature(oqs_alg) as signer:
            pub = signer.generate_keypair()
            sec = signer.export_secret_key()
            return pub, sec
    except Exception as e:
        raise PQCBackendError(f"liboqs keygen failed for {oqs_alg!r}") from e


def liboqs_sign(qid_alg: str, payload: bytes, private_key: bytes) -> bytes:
    """
    Real liboqs signing.

    private_key must be the liboqs secret key bytes for the chosen oqs algorithm.
    """
    oqs = _import_oqs()
    oqs_alg = _oqs_alg_for(qid_alg)

    try:
        # Many liboqs-python builds support constructing Signature with a secret key.
        with oqs.Signature(oqs_alg, private_key) as signer:
            return signer.sign(payload)
    except TypeError:
        # Fail closed if the wrapper API differs on this platform.
        raise PQCBackendError(
            f"liboqs-python Signature({oqs_alg!r}, private_key) not supported on this platform"
        )
    except Exception as e:
        raise PQCBackendError(f"liboqs sign failed for {oqs_alg!r}") from e


def liboqs_verify(qid_alg: str, payload: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Real liboqs verification.

    Verification is boolean; any exception must fail-closed (False).
    """
    try:
        oqs = _import_oqs()
        oqs_alg = _oqs_alg_for(qid_alg)
        with oqs.Signature(oqs_alg) as verifier:
            return bool(verifier.verify(payload, signature, public_key))
    except Exception:
        return False


def enforce_no_silent_fallback_for_alg(alg: str) -> None:
    """
    Guardrail: if user explicitly selects a real PQC backend, we must not
    proceed with stub signing/verifying for PQC algorithms.

    After wiring is present, this function validates backend selection only.
    Real usage is enforced by qid.crypto routing to liboqs paths when selected.
    """
    backend = selected_backend()
    if backend is None:
        return

    if backend != "liboqs":
        raise PQCBackendError(f"Unknown QID_PQC_BACKEND: {backend!r}")

    # Only relevant for PQC algs; DEV remains dev-only.
    if alg in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
        return
