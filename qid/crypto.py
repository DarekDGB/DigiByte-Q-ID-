"""
Crypto helpers for DigiByte Q-ID.

Contract goals:
- Deterministic signing input: canonical JSON bytes only.
- Algorithm IDs are explicit and stable.
- Signature format is explicit envelope (v1), fail-closed.
- No silent fallback or downgrade.
- Hybrid signatures are strict AND.

CI-safe rule:
- generate_keypair() must not require oqs/liboqs.
- Real backend use is opt-in via QID_PQC_BACKEND.
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
_LEGACY_HYBRID_ALGO = "hybrid-dev-ml-dsa"

_ALLOWED_ALGOS = {DEV_ALGO, ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO, _LEGACY_HYBRID_ALGO}
_SIG_ENVELOPE_VERSION = 1


@dataclass(frozen=True)
class QIDKeyPair:
    algorithm: str
    secret_key: str
    public_key: str


def generate_dev_keypair() -> QIDKeyPair:
    return generate_keypair(DEV_ALGO)


def _canonical_json(data: Mapping[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _envelope_encode(obj: Dict[str, Any]) -> str:
    return _b64encode(_canonical_json(obj))


def _envelope_decode(sig: str) -> Dict[str, Any] | None:
    try:
        raw = _b64decode(sig)
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _normalize_alg(alg: str) -> str:
    return HYBRID_ALGO if alg == _LEGACY_HYBRID_ALGO else alg


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
    exp_ml = hmac.new(s1, msg, hashlib.sha256).digest()
    exp_fa = hmac.new(s2, msg, hashlib.sha512).digest()
    return hmac.compare_digest(exp_ml, sigs[ML_DSA_ALGO]) and hmac.compare_digest(exp_fa, sigs[FALCON_ALGO])


def generate_keypair(algorithm: str = DEV_ALGO) -> QIDKeyPair:
    """
    CI-safe key generation.

    NOTE: This does not require oqs/liboqs. It produces placeholder keys for PQC
    algorithms so the protocol and tests can run everywhere.
    """
    if algorithm not in _ALLOWED_ALGOS:
        raise ValueError(f"Unknown Q-ID algorithm: {algorithm!r}")

    alg = _normalize_alg(algorithm)

    if alg == DEV_ALGO:
        secret = secrets.token_bytes(32)
    elif alg in (ML_DSA_ALGO, FALCON_ALGO):
        secret = secrets.token_bytes(64)
    elif alg == HYBRID_ALGO:
        secret = secrets.token_bytes(64)
    else:
        raise ValueError(f"Unsupported Q-ID algorithm: {algorithm!r}")

    pub = hashlib.sha256(secret).digest()
    return QIDKeyPair(algorithm=alg, secret_key=_b64encode(secret), public_key=_b64encode(pub))


def sign_payload(payload: Dict[str, Any], keypair: QIDKeyPair, *, hybrid_container_b64: Optional[str] = None) -> str:
    """
    Sign payload and return Crypto Envelope v1.

    hybrid_container_b64:
      - Optional base64(JSON) Hybrid Key Container v1
      - REQUIRED when QID_PQC_BACKEND is selected and alg is HYBRID_ALGO
      - Not required in stub mode (CI-safe)
    """
    from qid.pqc_backends import PQCBackendError, enforce_no_silent_fallback_for_alg, liboqs_sign, selected_backend
    from qid.hybrid_key_container import try_decode_container

    alg = _normalize_alg(keypair.algorithm)
    if alg not in _ALLOWED_ALGOS:
        raise ValueError(f"Unknown Q-ID algorithm: {keypair.algorithm!r}")

    msg = _canonical_json(payload)
    backend = selected_backend()

    # Real backend selected: enforce no silent fallback for PQC algs.
    if backend is not None and alg in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
        enforce_no_silent_fallback_for_alg(alg)

        if alg in (ML_DSA_ALGO, FALCON_ALGO):
            sec = _b64decode(keypair.secret_key)
            sig = liboqs_sign(alg, msg, sec)
            return _envelope_encode({"v": _SIG_ENVELOPE_VERSION, "alg": alg, "sig": _b64encode(sig)})

        # HYBRID with real backend requires explicit container (contract-locked)
        if hybrid_container_b64 is None:
            raise PQCBackendError("Hybrid signing requires hybrid_container_b64 when QID_PQC_BACKEND is selected")

        container = try_decode_container(hybrid_container_b64)
        if container is None:
            raise PQCBackendError("Invalid hybrid_container_b64 (failed to decode/validate)")

        # Container must be the hybrid alg
        if container.alg != HYBRID_ALGO:
            raise PQCBackendError("Hybrid container alg mismatch")

        # Sign with BOTH component secret keys (stored in container in this implementation)
        if container.ml_dsa.secret_key is None or container.falcon.secret_key is None:
            raise PQCBackendError("Hybrid container missing secret keys (ml_dsa/falcon)")

        ml_sec = _b64decode(container.ml_dsa.secret_key) if container.ml_dsa.secret_key else b""
        fa_sec = _b64decode(container.falcon.secret_key) if container.falcon.secret_key else b""

        sig_ml = liboqs_sign(ML_DSA_ALGO, msg, ml_sec)
        sig_fa = liboqs_sign(FALCON_ALGO, msg, fa_sec)

        return _envelope_encode(
            {
                "v": _SIG_ENVELOPE_VERSION,
                "alg": HYBRID_ALGO,
                "sigs": {ML_DSA_ALGO: _b64encode(sig_ml), FALCON_ALGO: _b64encode(sig_fa)},
            }
        )

    # Default stub signing (CI-safe)
    secret = _b64decode(keypair.secret_key)

    if alg == DEV_ALGO:
        sig = _stub_sign_dev(msg, secret)
        return _envelope_encode({"v": _SIG_ENVELOPE_VERSION, "alg": DEV_ALGO, "sig": _b64encode(sig)})

    if alg in (ML_DSA_ALGO, FALCON_ALGO):
        sig = _stub_sign_pqc(msg, secret, alg)
        return _envelope_encode({"v": _SIG_ENVELOPE_VERSION, "alg": alg, "sig": _b64encode(sig)})

    if alg == HYBRID_ALGO:
        sigs = _stub_sign_hybrid(msg, secret)
        return _envelope_encode(
            {"v": _SIG_ENVELOPE_VERSION, "alg": HYBRID_ALGO, "sigs": {k: _b64encode(v) for k, v in sigs.items()}}
        )

    raise ValueError(f"Unsupported algorithm for signing: {keypair.algorithm!r}")


def verify_payload(payload: Dict[str, Any], signature: str, keypair: QIDKeyPair, *, hybrid_container_b64: Optional[str] = None) -> bool:
    """
    Verify Crypto Envelope v1. Fail-closed.

    hybrid_container_b64:
      - Optional base64(JSON) Hybrid Key Container v1
      - REQUIRED when QID_PQC_BACKEND is selected and alg is HYBRID_ALGO
    """
    from qid.pqc_backends import PQCBackendError, enforce_no_silent_fallback_for_alg, liboqs_verify, selected_backend
    from qid.hybrid_key_container import try_decode_container

    env = _envelope_decode(signature)
    if env is None:
        return False
    if env.get("v") != _SIG_ENVELOPE_VERSION:
        return False

    env_alg = env.get("alg")
    if not isinstance(env_alg, str):
        return False
    env_alg = _normalize_alg(env_alg)

    kp_alg = _normalize_alg(keypair.algorithm)
    if env_alg != kp_alg:
        return False
    if env_alg not in _ALLOWED_ALGOS:
        return False

    msg = _canonical_json(payload)
    backend = selected_backend()

    if backend is not None and env_alg in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
        try:
            enforce_no_silent_fallback_for_alg(env_alg)
        except PQCBackendError:
            return False

        if env_alg in (ML_DSA_ALGO, FALCON_ALGO):
            sig_b64 = env.get("sig")
            if not isinstance(sig_b64, str):
                return False
            try:
                sig_bytes = _b64decode(sig_b64)
            except Exception:
                return False
            pub = _b64decode(keypair.public_key)
            try:
                return liboqs_verify(env_alg, msg, sig_bytes, pub)
            except PQCBackendError:
                return False

        # HYBRID real verification requires container
        if hybrid_container_b64 is None:
            return False

        container = try_decode_container(hybrid_container_b64)
        if container is None:
            return False
        if container.alg != HYBRID_ALGO:
            return False

        sigs = env.get("sigs")
        if not isinstance(sigs, dict):
            return False
        if set(sigs.keys()) != {ML_DSA_ALGO, FALCON_ALGO}:
            return False

        try:
            sig_ml = _b64decode(sigs[ML_DSA_ALGO])
            sig_fa = _b64decode(sigs[FALCON_ALGO])
        except Exception:
            return False

        try:
            pub_ml = _b64decode(container.ml_dsa.public_key)
            pub_fa = _b64decode(container.falcon.public_key)
        except Exception:
            return False

        try:
            ok_ml = liboqs_verify(ML_DSA_ALGO, msg, sig_ml, pub_ml)
            ok_fa = liboqs_verify(FALCON_ALGO, msg, sig_fa, pub_fa)
            return bool(ok_ml and ok_fa)
        except PQCBackendError:
            return False

    # Default stub verification
    secret = _b64decode(keypair.secret_key)

    if env_alg in (DEV_ALGO, ML_DSA_ALGO, FALCON_ALGO):
        sig_b64 = env.get("sig")
        if not isinstance(sig_b64, str):
            return False
        try:
            sig_bytes = _b64decode(sig_b64)
        except Exception:
            return False
        if env_alg == DEV_ALGO:
            return _stub_verify_dev(msg, secret, sig_bytes)
        return _stub_verify_pqc(msg, secret, sig_bytes, env_alg)

    if env_alg == HYBRID_ALGO:
        sigs = env.get("sigs")
        if not isinstance(sigs, dict):
            return False
        if set(sigs.keys()) != {ML_DSA_ALGO, FALCON_ALGO}:
            return False

        decoded: Dict[str, bytes] = {}
        for k in (ML_DSA_ALGO, FALCON_ALGO):
            v = sigs.get(k)
            if not isinstance(v, str):
                return False
            try:
                decoded[k] = _b64decode(v)
            except Exception:
                return False

        return _stub_verify_hybrid(msg, secret, decoded)

    return False
