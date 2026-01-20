"""
Crypto helpers for DigiByte Q-ID.

Contract goals:
- Deterministic signing input: canonical JSON bytes only.
- Signature format is explicit envelope (v1), fail-closed.
- No silent fallback or downgrade.
- Hybrid signatures are strict AND.

CI-safe rule:
- generate_keypair() MUST NOT require oqs/liboqs.
- Real backend enforcement happens at sign/verify time.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional


DEV_ALGO = "dev-hmac-sha256"
ML_DSA_ALGO = "pqc-ml-dsa"
FALCON_ALGO = "pqc-falcon"
HYBRID_ALGO = "pqc-hybrid-ml-dsa-falcon"

# Legacy alias expected by tests/back-compat
_LEGACY_HYBRID_ALGO = "hybrid-dev-ml-dsa"

_ALLOWED_ALGOS = {DEV_ALGO, ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO, _LEGACY_HYBRID_ALGO}
_SIG_ENVELOPE_VERSION = 1


@dataclass(frozen=True)
class QIDKeyPair:
    algorithm: str
    secret_key: str  # base64
    public_key: str  # base64


def _b64encode(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64decode(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _canonical_json(obj: Mapping[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _normalize_alg(alg: str) -> str:
    if alg == _LEGACY_HYBRID_ALGO:
        return HYBRID_ALGO
    return alg


def _envelope_encode(d: Mapping[str, Any]) -> str:
    return _b64encode(_canonical_json(d))


def _envelope_decode(sig_b64: str) -> Dict[str, Any]:
    try:
        raw = _b64decode(sig_b64)
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict):
            raise ValueError("envelope must be object")
        return obj
    except Exception as e:
        raise ValueError("invalid signature envelope") from e


# ---------------- CI-safe stub crypto ----------------


def _stub_sign_dev(msg: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, msg, hashlib.sha256).digest()


def _stub_verify_dev(msg: bytes, secret: bytes, sig: bytes) -> bool:
    expected = hmac.new(secret, msg, hashlib.sha256).digest()
    return hmac.compare_digest(expected, sig)


def _stub_sign_pqc(msg: bytes, secret: bytes, alg: str) -> bytes:
    core = hmac.new(secret, msg, hashlib.sha512).digest()
    return alg.encode("ascii") + b":" + core


def _stub_verify_pqc(msg: bytes, secret: bytes, sig: bytes, alg: str) -> bool:
    prefix = alg.encode("ascii") + b":"
    if not sig.startswith(prefix):
        return False
    core = sig[len(prefix) :]
    expected = hmac.new(secret, msg, hashlib.sha512).digest()
    return hmac.compare_digest(expected, core)


def _stub_sign_hybrid(msg: bytes, secret: bytes) -> Dict[str, bytes]:
    if len(secret) < 64:
        raise ValueError("Hybrid secret key must be at least 64 bytes")
    s1, s2 = secret[:32], secret[32:64]
    return {
        ML_DSA_ALGO: hmac.new(s1, msg, hashlib.sha256).digest(),
        FALCON_ALGO: hmac.new(s2, msg, hashlib.sha512).digest(),
    }


def _stub_verify_hybrid(msg: bytes, secret: bytes, sigs: Mapping[str, bytes]) -> bool:
    if len(secret) < 64:
        return False
    if set(sigs.keys()) != {ML_DSA_ALGO, FALCON_ALGO}:
        return False
    s1, s2 = secret[:32], secret[32:64]
    exp1 = hmac.new(s1, msg, hashlib.sha256).digest()
    exp2 = hmac.new(s2, msg, hashlib.sha512).digest()
    return hmac.compare_digest(exp1, sigs[ML_DSA_ALGO]) and hmac.compare_digest(exp2, sigs[FALCON_ALGO])


# ---------------- Public API ----------------


def generate_dev_keypair() -> QIDKeyPair:
    return generate_keypair(DEV_ALGO)


def generate_keypair(algorithm: str = DEV_ALGO) -> QIDKeyPair:
    """
    CI-safe key generation.

    IMPORTANT: This function never imports oqs and never requires QID_PQC_BACKEND.
    Real backend enforcement happens at sign/verify time.
    """
    if algorithm not in _ALLOWED_ALGOS:
        raise ValueError(f"Unknown Q-ID algorithm: {algorithm!r}")

    alg = _normalize_alg(algorithm)

    if alg == DEV_ALGO:
        secret = secrets.token_bytes(32)
    elif alg in (ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO):
        secret = secrets.token_bytes(64)
    else:
        raise ValueError(f"Unsupported Q-ID algorithm: {algorithm!r}")

    pub = hashlib.sha256(secret).digest()
    return QIDKeyPair(algorithm=alg, secret_key=_b64encode(secret), public_key=_b64encode(pub))


def sign_payload(payload: Dict[str, Any], keypair: QIDKeyPair, *, hybrid_container_b64: Optional[str] = None) -> str:
    from qid.pqc_backends import PQCBackendError, enforce_no_silent_fallback_for_alg, liboqs_sign, selected_backend
    from qid.hybrid_key_container import try_decode_container

    alg = _normalize_alg(keypair.algorithm)
    if alg not in _ALLOWED_ALGOS:
        raise ValueError(f"Unknown Q-ID algorithm: {keypair.algorithm!r}")

    msg = _canonical_json(payload)
    backend = selected_backend()

    if backend is not None and alg in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
        # Real backend selected: enforce no silent fallback at signing time.
        enforce_no_silent_fallback_for_alg(alg)

        if alg in (ML_DSA_ALGO, FALCON_ALGO):
            sec = _b64decode(keypair.secret_key)
            sig = liboqs_sign(alg, msg, sec)
            return _envelope_encode({"v": _SIG_ENVELOPE_VERSION, "alg": alg, "sig": _b64encode(sig)})

        if hybrid_container_b64 is None:
            raise PQCBackendError("Hybrid signing requires hybrid_container_b64 when QID_PQC_BACKEND is selected")

        container = try_decode_container(hybrid_container_b64)
        if container is None:
            raise PQCBackendError("Invalid hybrid_container_b64 (failed to decode/validate)")
        if container.alg != HYBRID_ALGO:
            raise PQCBackendError("Hybrid container alg mismatch")
        if container.ml_dsa.secret_key is None or container.falcon.secret_key is None:
            raise PQCBackendError("Hybrid container missing secret keys (ml_dsa/falcon)")

        ml_sec = _b64decode(container.ml_dsa.secret_key)
        fa_sec = _b64decode(container.falcon.secret_key)

        sig_ml = liboqs_sign(ML_DSA_ALGO, msg, ml_sec)
        sig_fa = liboqs_sign(FALCON_ALGO, msg, fa_sec)

        return _envelope_encode(
            {
                "v": _SIG_ENVELOPE_VERSION,
                "alg": HYBRID_ALGO,
                "sigs": {ML_DSA_ALGO: _b64encode(sig_ml), FALCON_ALGO: _b64encode(sig_fa)},
            }
        )

    # Stub signing (CI-safe)
    secret = _b64decode(keypair.secret_key)

    if alg == DEV_ALGO:
        sig = _stub_sign_dev(msg, secret)
        return _envelope_encode({"v": _SIG_ENVELOPE_VERSION, "alg": DEV_ALGO, "sig": _b64encode(sig)})

    if alg in (ML_DSA_ALGO, FALCON_ALGO):
        sig = _stub_sign_pqc(msg, secret, alg)
        return _envelope_encode({"v": _SIG_ENVELOPE_VERSION, "alg": alg, "sig": _b64encode(sig)})

    if alg == HYBRID_ALGO:
        sigs = _stub_sign_hybrid(msg, secret)
        return _envelope_encode({"v": _SIG_ENVELOPE_VERSION, "alg": HYBRID_ALGO, "sigs": {k: _b64encode(v) for k, v in sigs.items()}})

    raise ValueError(f"Unsupported algorithm for signing: {keypair.algorithm!r}")


def verify_payload(payload: Dict[str, Any], signature: str, keypair: QIDKeyPair, *, hybrid_container_b64: Optional[str] = None) -> bool:
    from qid.pqc_backends import PQCBackendError, enforce_no_silent_fallback_for_alg, liboqs_verify, selected_backend
    from qid.hybrid_key_container import try_decode_container

    try:
        env = _envelope_decode(signature)
        if env.get("v") != _SIG_ENVELOPE_VERSION:
            return False
        alg = _normalize_alg(str(env.get("alg")))
    except Exception:
        return False

    msg = _canonical_json(payload)
    backend = selected_backend()

    if backend is not None and alg in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
        try:
            enforce_no_silent_fallback_for_alg(alg)

            if alg in (ML_DSA_ALGO, FALCON_ALGO):
                sig_b64 = env.get("sig")
                if not isinstance(sig_b64, str):
                    return False
                sig = _b64decode(sig_b64)
                pub = _b64decode(keypair.public_key)
                return liboqs_verify(alg, msg, sig, pub)

            # Hybrid verify requires container (contract-locked)
            if hybrid_container_b64 is None:
                return False
            container = try_decode_container(hybrid_container_b64)
            if container is None or container.alg != HYBRID_ALGO:
                return False

            sigs = env.get("sigs")
            if not isinstance(sigs, dict):
                return False
            s1 = sigs.get(ML_DSA_ALGO)
            s2 = sigs.get(FALCON_ALGO)
            if not isinstance(s1, str) or not isinstance(s2, str):
                return False

            sig_ml = _b64decode(s1)
            sig_fa = _b64decode(s2)
            pub_ml = _b64decode(container.ml_dsa.public_key)
            pub_fa = _b64decode(container.falcon.public_key)

            return bool(
                liboqs_verify(ML_DSA_ALGO, msg, sig_ml, pub_ml)
                and liboqs_verify(FALCON_ALGO, msg, sig_fa, pub_fa)
            )
        except PQCBackendError:
            return False
        except Exception:
            return False

    # Stub verification (CI-safe)
    try:
        secret = _b64decode(keypair.secret_key)

        if alg == DEV_ALGO:
            s = env.get("sig")
            if not isinstance(s, str):
                return False
            return _stub_verify_dev(msg, secret, _b64decode(s))

        if alg in (ML_DSA_ALGO, FALCON_ALGO):
            s = env.get("sig")
            if not isinstance(s, str):
                return False
            return _stub_verify_pqc(msg, secret, _b64decode(s), alg)

        if alg == HYBRID_ALGO:
            sigs = env.get("sigs")
            if not isinstance(sigs, dict):
                return False
            try:
                sig_map = {k: _b64decode(v) for k, v in sigs.items() if isinstance(v, str)}
            except Exception:
                return False
            return _stub_verify_hybrid(msg, secret, sig_map)

        return False
    except Exception:
        return False
