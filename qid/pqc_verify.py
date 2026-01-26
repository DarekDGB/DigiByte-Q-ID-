from __future__ import annotations

import base64
import json
from typing import Any, Mapping

from qid.pqc_backends import (
    FALCON_ALGO,
    HYBRID_ALGO,
    ML_DSA_ALGO,
    PQCBackendError,
    enforce_no_silent_fallback_for_alg,
    liboqs_verify,
    selected_backend,
)


def _b64url_decode(s: str) -> bytes:
    """Decode base64url without padding."""
    if not isinstance(s, str):
        raise ValueError('invalid base64url')
    s = s.strip()
    if s == '':
        raise ValueError('invalid base64url')
    pad = '=' * ((4 - (len(s) % 4)) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except Exception:
        raise ValueError('invalid base64url') from None


def canonical_payload_bytes(payload: Mapping[str, Any]) -> bytes:
    """Canonical JSON bytes for signing/verifying."""
    return json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')


def _payload_for_pqc(src: Mapping[str, Any]) -> dict[str, Any]:
    """Remove signature fields so the signed message is non-circular."""
    out = dict(src)
    out.pop('pqc_sig', None)
    out.pop('pqc_sig_ml_dsa', None)
    out.pop('pqc_sig_falcon', None)
    return out


def _decode_pubkey(binding_payload: Mapping[str, Any], which: str) -> bytes:
    pubkeys = binding_payload.get('pqc_pubkeys')
    if not isinstance(pubkeys, dict):
        raise ValueError('missing pqc_pubkeys')
    v = pubkeys.get(which)
    if not isinstance(v, str) or not v:
        raise ValueError('missing pubkey')
    return _b64url_decode(v)


def _policy_allows_alg(qid_alg: str, policy: Any) -> bool:
    if not isinstance(policy, str):
        return False
    p = policy.strip().lower()
    if qid_alg == ML_DSA_ALGO:
        return p in {'ml-dsa', 'hybrid'}
    if qid_alg == FALCON_ALGO:
        return p in {'falcon', 'hybrid'}
    if qid_alg == HYBRID_ALGO:
        return p == 'hybrid'
    return False


def verify_pqc_login(*args: Any, **kwargs: Any) -> bool:
    """Verify PQC login signature(s).

    Supported call shapes:
    - verify_pqc_login(login_payload=..., binding_env=...)
    - verify_pqc_login(binding_payload, login_payload)

    Returns True on successful verification, otherwise False (fail-closed).
    """
    # Determine call shape.
    if args:
        # Positional form: (binding_payload, login_payload)
        if len(args) != 2 or kwargs:
            return False
        binding_payload = args[0]
        login_payload = args[1]
        if not isinstance(binding_payload, Mapping) or not isinstance(login_payload, Mapping):
            return False
        msg = canonical_payload_bytes(binding_payload)
        binding = binding_payload
        login = dict(login_payload)
    else:
        # Keyword form: (login_payload=..., binding_env=...)
        login_payload = kwargs.get('login_payload')
        binding_env = kwargs.get('binding_env')
        if not isinstance(login_payload, Mapping) or not isinstance(binding_env, Mapping):
            return False
        binding_payload = binding_env.get('payload')
        if not isinstance(binding_payload, Mapping):
            return False
        msg = canonical_payload_bytes(_payload_for_pqc(login_payload))
        binding = binding_payload
        login = dict(login_payload)

    backend = selected_backend()
    if backend is None:
        return False
    if backend != 'liboqs':
        # Unknown backends fail-closed.
        return False

    alg = login.get('pqc_alg')
    if not isinstance(alg, str):
        return False

    policy = binding.get('policy')
    if not _policy_allows_alg(alg, policy):
        return False

    try:
        if alg == HYBRID_ALGO:
            sig_field = login.get('pqc_sig')
            if isinstance(sig_field, Mapping):
                sig_ml_s = sig_field.get('ml_dsa')
                sig_fa_s = sig_field.get('falcon')
            else:
                sig_ml_s = login.get('pqc_sig_ml_dsa')
                sig_fa_s = login.get('pqc_sig_falcon')

            if not isinstance(sig_ml_s, str) or not isinstance(sig_fa_s, str):
                return False

            sig_ml = _b64url_decode(sig_ml_s)
            sig_fa = _b64url_decode(sig_fa_s)
            pub_ml = _decode_pubkey(binding, 'ml_dsa')
            pub_fa = _decode_pubkey(binding, 'falcon')

            enforce_no_silent_fallback_for_alg(ML_DSA_ALGO)
            enforce_no_silent_fallback_for_alg(FALCON_ALGO)

            ok_ml = bool(liboqs_verify(ML_DSA_ALGO, msg, sig_ml, pub_ml))
            ok_fa = bool(liboqs_verify(FALCON_ALGO, msg, sig_fa, pub_fa))
            return ok_ml and ok_fa

        if alg == ML_DSA_ALGO:
            sig_s = login.get('pqc_sig')
            if not isinstance(sig_s, str):
                sig_s = login.get('pqc_sig_ml_dsa')
            if not isinstance(sig_s, str):
                return False
            sig = _b64url_decode(sig_s)
            pub = _decode_pubkey(binding, 'ml_dsa')
            enforce_no_silent_fallback_for_alg(ML_DSA_ALGO)
            return bool(liboqs_verify(ML_DSA_ALGO, msg, sig, pub))

        if alg == FALCON_ALGO:
            sig_s = login.get('pqc_sig')
            if not isinstance(sig_s, str):
                sig_s = login.get('pqc_sig_falcon')
            if not isinstance(sig_s, str):
                return False
            sig = _b64url_decode(sig_s)
            pub = _decode_pubkey(binding, 'falcon')
            enforce_no_silent_fallback_for_alg(FALCON_ALGO)
            return bool(liboqs_verify(FALCON_ALGO, msg, sig, pub))

        return False

    except (ValueError, PQCBackendError):
        return False
    except Exception:
        return False
