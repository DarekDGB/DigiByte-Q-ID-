"""Fail-closed PQC verification for Q-ID login binding."""

from __future__ import annotations

from typing import Any

from qid.pqc_backends import (
    FALCON_ALGO,
    HYBRID_ALGO,
    ML_DSA_ALGO,
    PQCBackendError,
    enforce_no_silent_fallback_for_alg,
    liboqs_verify,
    selected_backend,
)
from qid.pqc_sign import _b64url_decode, canonical_payload_bytes


def _payload_for_pqc(login_payload: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of the payload with PQC signature fields removed (non-circular)."""
    d = dict(login_payload)
    # remove both the algo selector and any signature material
    d.pop("pqc_alg", None)
    d.pop("pqc_sig", None)
    d.pop("pqc_sig_ml_dsa", None)
    d.pop("pqc_sig_falcon", None)
    return d


def _decode_pubkey(binding_env: dict[str, Any], which: str) -> bytes:
    payload = binding_env.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("binding_env.payload must be dict")
    pubkeys = payload.get("pqc_pubkeys")
    if not isinstance(pubkeys, dict):
        raise ValueError("binding_env.payload.pqc_pubkeys must be dict")
    b64u = pubkeys.get(which)
    if not isinstance(b64u, str) or not b64u:
        raise ValueError("missing pubkey")
    return _b64url_decode(b64u)


def _decode_sig(login_payload: dict[str, Any], which: str) -> bytes:
    b64u = login_payload.get(which)
    if not isinstance(b64u, str) or not b64u:
        raise ValueError("missing signature")
    return _b64url_decode(b64u)


def verify_pqc_login(*, login_payload: dict[str, Any], binding_env: dict[str, Any]) -> bool:
    """
    Verify the PQC component of a login response.

    Contract:
    - MUST be fail-closed: any internal error -> False
    - MUST NOT silently fall back when a real backend is selected
    """
    try:
        backend = selected_backend()
        if backend is None:
            return False
        if backend != "liboqs":
            raise PQCBackendError(f"Unknown QID_PQC_BACKEND: {backend!r}")

        if not isinstance(login_payload, dict) or not isinstance(binding_env, dict):
            return False

        alg = login_payload.get("pqc_alg")
        if not isinstance(alg, str):
            return False

        # Early guardrail for chosen algorithm.
        enforce_no_silent_fallback_for_alg(alg)

        # Signature message is the canonical bytes of the binding payload (without PQC signatures).
        msg = canonical_payload_bytes(_payload_for_pqc(login_payload))

        payload = binding_env.get("payload")
        if not isinstance(payload, dict):
            return False
        policy = payload.get("policy")
        if not isinstance(policy, str):
            return False

        if alg == ML_DSA_ALGO:
            # ML-DSA policy must match
            if policy not in {"ml-dsa", "hybrid"}:
                return False
            pub = _decode_pubkey(binding_env, "ml_dsa")
            sig = _decode_sig(login_payload, "pqc_sig")
            return bool(liboqs_verify(ML_DSA_ALGO, msg, sig, pub))

        if alg == FALCON_ALGO:
            if policy not in {"falcon", "hybrid"}:
                return False
            pub = _decode_pubkey(binding_env, "falcon")
            sig = _decode_sig(login_payload, "pqc_sig")
            return bool(liboqs_verify(FALCON_ALGO, msg, sig, pub))

        if alg == HYBRID_ALGO:
            if policy != "hybrid":
                return False

            # Accept both shapes:
            # - new: login_payload["pqc_sig"] is {"ml_dsa": "...", "falcon": "..."}
            # - legacy: login_payload has "pqc_sig_ml_dsa" and "pqc_sig_falcon"
            sig_ml_b64u: Any
            sig_fa_b64u: Any

            sig_obj = login_payload.get("pqc_sig")
            if isinstance(sig_obj, dict):
                sig_ml_b64u = sig_obj.get("ml_dsa")
                sig_fa_b64u = sig_obj.get("falcon")
            else:
                sig_ml_b64u = login_payload.get("pqc_sig_ml_dsa")
                sig_fa_b64u = login_payload.get("pqc_sig_falcon")

            if not isinstance(sig_ml_b64u, str) or not isinstance(sig_fa_b64u, str):
                return False

            sig_ml = _b64url_decode(sig_ml_b64u)
            sig_fa = _b64url_decode(sig_fa_b64u)

            pub_ml = _decode_pubkey(binding_env, "ml_dsa")
            pub_fa = _decode_pubkey(binding_env, "falcon")

            # strict AND
            ok1 = bool(liboqs_verify(ML_DSA_ALGO, msg, sig_ml, pub_ml))
            ok2 = bool(liboqs_verify(FALCON_ALGO, msg, sig_fa, pub_fa))
            return ok1 and ok2

        # Unknown PQC algorithm => fail-closed
        return False

    except (ValueError, PQCBackendError):
        # Fail-closed: never raise from the verifier surface.
        return False
    except Exception:
        return False
