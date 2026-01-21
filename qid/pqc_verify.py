from __future__ import annotations

import base64
import json
from typing import Any, Dict, Mapping, Optional, Tuple

from .pqc_backends import (
    ML_DSA_ALGO,
    FALCON_ALGO,
    HYBRID_ALGO,
    PQCBackendError,
    enforce_no_silent_fallback_for_alg,
    liboqs_verify,
    selected_backend,
)

def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))

def canonical_payload_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _decode_pubkey(b64u: str) -> bytes:
    if not isinstance(b64u, str) or not b64u:
        raise ValueError("missing PQC pubkey")
    return _b64url_decode(b64u)

def _decode_sig(b64u: str) -> bytes:
    if not isinstance(b64u, str) or not b64u:
        raise ValueError("missing PQC signature")
    return _b64url_decode(b64u)

def verify_pqc_login(
    *,
    login_payload: Mapping[str, Any],
    binding_env: Mapping[str, Any],
) -> bool:
    """
    Verify PQC signatures for dual-proof logins (fail-closed).

    CI-safe policy:
    - If no backend selected, return False (cannot claim PQC verification).
    - If backend selected, enforce no silent fallback and verify via liboqs.
    """
    try:
        backend = selected_backend()
        if backend is None:
            return False

        # Pull binding payload
        b_payload = binding_env.get("payload")
        if not isinstance(b_payload, Mapping):
            return False

        policy = b_payload.get("policy")
        pqc_keys = b_payload.get("pqc_pubkeys")
        if not isinstance(policy, str) or not isinstance(pqc_keys, Mapping):
            return False

        msg = canonical_payload_bytes(login_payload)

        # Determine algorithm requested by login payload
        alg = login_payload.get("pqc_alg")
        if not isinstance(alg, str):
            return False

        if alg not in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
            return False

        # Enforce "no silent fallback" for PQC algs when backend selected
        enforce_no_silent_fallback_for_alg(alg)

        if alg == ML_DSA_ALGO:
            if policy not in {"ml-dsa", "hybrid"}:
                return False
            pub = _decode_pubkey(pqc_keys.get("ml_dsa"))  # type: ignore[arg-type]
            sig = _decode_sig(login_payload.get("pqc_sig"))  # type: ignore[arg-type]
            return bool(liboqs_verify(ML_DSA_ALGO, msg, sig, pub))

        if alg == FALCON_ALGO:
            if policy not in {"falcon", "hybrid"}:
                return False
            pub = _decode_pubkey(pqc_keys.get("falcon"))  # type: ignore[arg-type]
            sig = _decode_sig(login_payload.get("pqc_sig"))  # type: ignore[arg-type]
            return bool(liboqs_verify(FALCON_ALGO, msg, sig, pub))

        # HYBRID strict AND
        if policy != "hybrid":
            return False
        pub_ml = _decode_pubkey(pqc_keys.get("ml_dsa"))  # type: ignore[arg-type]
        pub_fa = _decode_pubkey(pqc_keys.get("falcon"))  # type: ignore[arg-type]
        sig_ml = _decode_sig(login_payload.get("pqc_sig_ml_dsa"))  # type: ignore[arg-type]
        sig_fa = _decode_sig(login_payload.get("pqc_sig_falcon"))  # type: ignore[arg-type]

        return bool(
            liboqs_verify(ML_DSA_ALGO, msg, sig_ml, pub_ml)
            and liboqs_verify(FALCON_ALGO, msg, sig_fa, pub_fa)
        )

    except (ValueError, PQCBackendError, TypeError):
        return False
    except Exception:
        return False
