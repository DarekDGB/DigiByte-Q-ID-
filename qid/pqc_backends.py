from __future__ import annotations

import os
from typing import Any


ML_DSA_ALGO = "pqc-ml-dsa"
FALCON_ALGO = "pqc-falcon"
HYBRID_ALGO = "pqc-hybrid-ml-dsa-falcon"


class PQCBackendError(RuntimeError):
    pass


class _OQSUnset:
    pass


_OQS_UNSET = _OQSUnset()
oqs: Any = _OQS_UNSET


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


def _pqc_tests_enabled() -> bool:
    return os.getenv("QID_PQC_TESTS") == "1"


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
        raise PQCBackendError("liboqs backend selected but oqs unavailable")

    if oqs is not _OQS_UNSET:
        _validate_oqs_module(oqs)
        return oqs

    try:
        import oqs as mod  # type: ignore
    except Exception:
        raise PQCBackendError("liboqs backend selected but oqs not installed") from None

    _validate_oqs_module(mod)
    oqs = mod
    return mod


def enforce_no_silent_fallback_for_alg(qid_alg: str) -> None:
    backend = selected_backend()
    if backend is None:
        return

    if backend != "liboqs":
        raise PQCBackendError(f"Unknown QID_PQC_BACKEND: {backend!r}")

    if not _pqc_tests_enabled():
        raise PQCBackendError("liboqs backend selected but PQC execution not enabled")


def liboqs_sign(qid_alg: str, msg: bytes, priv: bytes) -> bytes:
    enforce_no_silent_fallback_for_alg(qid_alg)

    mod = _import_oqs()
    candidates = _oqs_alg_candidates_for(qid_alg)

    for oqs_alg in candidates:
        try:
            if qid_alg == ML_DSA_ALGO:
                from qid.pqc.pqc_ml_dsa import sign_ml_dsa
                return sign_ml_dsa(oqs=mod, msg=msg, priv=priv, oqs_alg=oqs_alg)

            if qid_alg == FALCON_ALGO:
                from qid.pqc.pqc_falcon import sign_falcon
                return sign_falcon(oqs=mod, msg=msg, priv=priv, oqs_alg=oqs_alg)
        except Exception:
            continue

    raise PQCBackendError("liboqs signing failed")


def liboqs_verify(qid_alg: str, msg: bytes, sig: bytes, pub: bytes) -> bool:
    try:
        enforce_no_silent_fallback_for_alg(qid_alg)
        mod = _import_oqs()
        candidates = _oqs_alg_candidates_for(qid_alg)

        for oqs_alg in candidates:
            try:
                if qid_alg == ML_DSA_ALGO:
                    from qid.pqc.pqc_ml_dsa import verify_ml_dsa
                    return bool(verify_ml_dsa(oqs=mod, msg=msg, sig=sig, pub=pub, oqs_alg=oqs_alg))

                if qid_alg == FALCON_ALGO:
                    from qid.pqc.pqc_falcon import verify_falcon
                    return bool(verify_falcon(oqs=mod, msg=msg, sig=sig, pub=pub, oqs_alg=oqs_alg))
            except Exception:
                continue
    except Exception:
        return False

    return False
