from __future__ import annotations

"""
PQC verification for DigiByte Q-ID dual-proof logins.

Contract:
- Fail-closed:
  - If no backend selected => False.
  - If backend selected but unavailable/misconfigured => False.
  - If payload missing required fields => False.
- No silent fallback:
  - If a real backend is selected, PQC algs MUST NOT degrade silently.
"""

import base64
import json
from typing import Any, Mapping

from .pqc_backends import (
    ML_DSA_ALGO,
    FALCON_ALGO,
    HYBRID_ALGO,
    PQCBackendError,
    enforce_no_silent_fallback_for_alg,
    liboqs_verify,
    selected_backend,
)

_SIG_FIELDS = {"pqc_sig", "pqc_sig_ml_dsa", "pqc_sig_falcon"}


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def canonical_payload_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _payload_for_pqc(login_payload: Mapping[str, Any]) -> dict[str, Any]:
    d = dict(login_payload)
    for k in _SIG_FIELDS:
        d.pop(k, None)
    return d


def _decode_pubkey(b64u: Any) -> bytes:
    if not isinstance(b64u, str) or not b64u:
        raise ValueError("missing PQC pubkey")
    return _b64url_decode(b64u)


def _decode_sig(b64u: Any) -> bytes:
    if not isinstance(b64u, str) or not b64u:
        raise ValueError("missing PQC signature")
    return _b64url_decode(b64u)


def verify_pqc_login(login_payload: Mapping[str, Any], binding_env: Mapping[str, Any]) -> bool:
    """
    NOTE: Must accept positional args (tests call it positionally).
    """
    try:
        backend = selected_backend()
        if backend is None:
            return False

        b_payload = binding_env.get("payload")
        if not isinstance(b_payload, Mapping):
            return False

        policy = b_payload.get("policy")
        pqc_keys = b_payload.get("pqc_pubkeys")
        if not isinstance(policy, str) or not isinstance(pqc_keys, Mapping):
            return False

        alg = login_payload.get("pqc_alg")
        if not isinstance(alg, str):
            return False
        if alg not in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
            return False

        enforce_no_silent_fallback_for_alg(alg)

        msg = canonical_payload_bytes(_payload_for_pqc(login_payload))

        if alg == ML_DSA_ALGO:
            if policy not in {"ml-dsa", "hybrid"}:
                return False
            pub = _decode_pubkey(pqc_keys.get("ml_dsa"))
            sig = _decode_sig(login_payload.get("pqc_sig"))
            return bool(liboqs_verify(ML_DSA_ALGO, msg, sig, pub))

        if alg == FALCON_ALGO:
            if policy not in {"falcon", "hybrid"}:
                return False
            pub = _decode_pubkey(pqc_keys.get("falcon"))
            sig = _decode_sig(login_payload.get("pqc_sig"))
            return bool(liboqs_verify(FALCON_ALGO, msg, sig, pub))

        if policy != "hybrid":
            return False

        pub_ml = _decode_pubkey(pqc_keys.get("ml_dsa"))
        pub_fa = _decode_pubkey(pqc_keys.get("falcon"))
        sig_ml = _decode_sig(login_payload.get("pqc_sig_ml_dsa"))
        sig_fa = _decode_sig(login_payload.get("pqc_sig_falcon"))

        return bool(
            liboqs_verify(ML_DSA_ALGO, msg, sig_ml, pub_ml)
            and liboqs_verify(FALCON_ALGO, msg, sig_fa, pub_fa)
        )

    except (ValueError, PQCBackendError, TypeError):
        return False
    except Exception:
        return False
