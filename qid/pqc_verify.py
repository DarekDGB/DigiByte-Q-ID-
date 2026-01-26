"""Fail-closed PQC verification for Q-ID login binding."""

from __future__ import annotations

from typing import Any, Mapping
import base64
import json

from qid.pqc_backends import (
    PQCBackendError,
    ML_DSA_ALGO,
    FALCON_ALGO,
    HYBRID_ALGO,
    enforce_no_silent_fallback_for_alg,
    liboqs_verify,
    selected_backend,
)


def _b64url_decode(s: str) -> bytes:
    s2 = s.encode("utf-8")
    pad = b"=" * ((4 - (len(s2) % 4)) % 4)
    return base64.urlsafe_b64decode(s2 + pad)


def _payload_for_pqc(src: Mapping[str, Any]) -> dict[str, Any]:
    """
    Remove signature fields so the signed message is non-circular.

    Tests expect pqc_alg to be removed too.
    """
    out = dict(src)
    out.pop("pqc_alg", None)
    out.pop("pqc_sig", None)
    out.pop("pqc_sig_ml_dsa", None)
    out.pop("pqc_sig_falcon", None)
    return out


def _decode_pubkey(binding_payload: Mapping[str, Any], which: str) -> bytes:
    pubkeys = binding_payload.get("pqc_pubkeys")
    if not isinstance(pubkeys, Mapping):
        raise ValueError("binding payload missing pqc_pubkeys")
    s = pubkeys.get(which)
    if not isinstance(s, str) or not s:
        raise ValueError("binding payload missing pubkey")
    return _b64url_decode(s)


def _decode_sig_field(login_payload: Mapping[str, Any], field: str) -> bytes:
    s = login_payload.get(field)
    if not isinstance(s, str) or not s:
        raise ValueError("login payload missing signature field")
    return _b64url_decode(s)


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    # Deterministic, minimal JSON
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def verify_pqc_login(*args: Any, **kwargs: Any) -> bool:
    """
    Fail-closed PQC login verification.

    Supports BOTH calling styles used across tests:
      - verify_pqc_login(login_payload, binding_env)
      - verify_pqc_login(login_payload=..., binding_env=...)
    """
    # Accept positional or keyword forms.
    login_payload = None
    binding_env = None

    if len(args) >= 1:
        login_payload = args[0]
    if len(args) >= 2:
        binding_env = args[1]

    if login_payload is None:
        login_payload = kwargs.get("login_payload")
    if binding_env is None:
        binding_env = kwargs.get("binding_env")

    try:
        if not isinstance(login_payload, Mapping) or not isinstance(binding_env, Mapping):
            return False

        backend = selected_backend()
        if backend is None:
            return False
        if backend != "liboqs":
            return False

        # binding_env must provide a binding payload under "payload"
        binding_payload = binding_env.get("payload")
        if not isinstance(binding_payload, Mapping):
            return False

        alg = login_payload.get("pqc_alg")
        if not isinstance(alg, str):
            return False

        # Guardrail: if backend selected, PQC must be real.
        enforce_no_silent_fallback_for_alg(alg)

        # Policy checks (fail closed)
        policy = binding_payload.get("policy")
        if not isinstance(policy, str):
            return False

        # Compute message bytes from sanitized binding payload
        msg = _canonical_bytes(_payload_for_pqc(binding_payload))

        if alg == ML_DSA_ALGO:
            if policy not in {"ml-dsa", "hybrid"}:
                return False
            sig = _decode_sig_field(login_payload, "pqc_sig")
            pub = _decode_pubkey(binding_payload, "ml_dsa")
            return bool(liboqs_verify(ML_DSA_ALGO, msg, sig, pub))

        if alg == FALCON_ALGO:
            if policy not in {"falcon", "hybrid"}:
                return False
            sig = _decode_sig_field(login_payload, "pqc_sig")
            pub = _decode_pubkey(binding_payload, "falcon")
            return bool(liboqs_verify(FALCON_ALGO, msg, sig, pub))

        if alg == HYBRID_ALGO:
            if policy != "hybrid":
                return False
            sig_ml = _decode_sig_field(login_payload, "pqc_sig_ml_dsa")
            sig_fa = _decode_sig_field(login_payload, "pqc_sig_falcon")
            pub_ml = _decode_pubkey(binding_payload, "ml_dsa")
            pub_fa = _decode_pubkey(binding_payload, "falcon")

            ok_ml = bool(liboqs_verify(ML_DSA_ALGO, msg, sig_ml, pub_ml))
            ok_fa = bool(liboqs_verify(FALCON_ALGO, msg, sig_fa, pub_fa))
            return bool(ok_ml and ok_fa)

        return False

    except (ValueError, PQCBackendError):
        return False
    except Exception:
        return False
