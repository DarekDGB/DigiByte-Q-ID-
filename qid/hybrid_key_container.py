"""
Hybrid Key Container for DigiByte Q-ID.

Purpose:
- Carry ML-DSA + Falcon public keys (and optionally secret keys) in a single
  base64(JSON) container used by HYBRID signing/verification.

Must be:
- Deterministic (canonical JSON)
- Strictly validated
- Fail-closed on decode
- Provide stable container hash for binding / auditing
- Provide a public-only view (no secret leakage)

Author: DarekDGB
License: MIT (see repo LICENSE)
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional, Union

from .crypto import HYBRID_ALGO


def _canonical_json(d: Dict[str, Any]) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64encode(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64decode(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _is_b64(s: str) -> bool:
    try:
        _b64decode(s)
        return True
    except Exception:
        return False


@dataclass(frozen=True)
class HybridComponent:
    public_key: str
    secret_key: Optional[str] = None


@dataclass(frozen=True)
class HybridKeyContainer:
    v: int
    alg: str
    kid: str
    ml_dsa: HybridComponent
    falcon: HybridComponent


def build_container(
    *,
    alg: str = HYBRID_ALGO,
    kid: str = "kid",
    ml_dsa_pub: str,
    falcon_pub: str,
    ml_dsa_secret_key: Optional[str] = None,
    falcon_secret_key: Optional[str] = None,
    # Back-compat parameter names
    ml_dsa_public_key: Optional[str] = None,
    falcon_public_key: Optional[str] = None,
    ml_dsa_secret: Optional[str] = None,
    falcon_secret: Optional[str] = None,
) -> HybridKeyContainer:
    if ml_dsa_public_key is not None:
        ml_dsa_pub = ml_dsa_public_key
    if falcon_public_key is not None:
        falcon_pub = falcon_public_key
    if ml_dsa_secret is not None:
        ml_dsa_secret_key = ml_dsa_secret
    if falcon_secret is not None:
        falcon_secret_key = falcon_secret

    if alg != HYBRID_ALGO:
        raise ValueError("Hybrid container alg must be pqc-hybrid-ml-dsa-falcon")
    if not isinstance(kid, str) or not kid:
        raise ValueError("kid must be non-empty string")

    if not isinstance(ml_dsa_pub, str) or not _is_b64(ml_dsa_pub):
        raise ValueError("ml_dsa_pub must be base64 string")
    if not isinstance(falcon_pub, str) or not _is_b64(falcon_pub):
        raise ValueError("falcon_pub must be base64 string")

    if ml_dsa_secret_key is not None and (not isinstance(ml_dsa_secret_key, str) or not _is_b64(ml_dsa_secret_key)):
        raise ValueError("ml_dsa_secret_key must be base64 string if provided")
    if falcon_secret_key is not None and (not isinstance(falcon_secret_key, str) or not _is_b64(falcon_secret_key)):
        raise ValueError("falcon_secret_key must be base64 string if provided")

    return HybridKeyContainer(
        v=1,
        alg=HYBRID_ALGO,
        kid=kid,
        ml_dsa=HybridComponent(public_key=ml_dsa_pub, secret_key=ml_dsa_secret_key),
        falcon=HybridComponent(public_key=falcon_pub, secret_key=falcon_secret_key),
    )


def encode_container(c: HybridKeyContainer) -> str:
    d = {
        "v": c.v,
        "alg": c.alg,
        "kid": c.kid,
        "ml_dsa": {"public_key": c.ml_dsa.public_key, "secret_key": c.ml_dsa.secret_key},
        "falcon": {"public_key": c.falcon.public_key, "secret_key": c.falcon.secret_key},
    }
    return _b64encode(_canonical_json(d))


def try_decode_container(b64: str) -> Optional[HybridKeyContainer]:
    try:
        return decode_container(b64)
    except Exception:
        return None


def decode_container(b64: str) -> HybridKeyContainer:
    try:
        raw = _b64decode(b64)
        obj = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise ValueError("Invalid hybrid container encoding") from e

    if not isinstance(obj, dict):
        raise ValueError("Hybrid container must be a JSON object")

    if obj.get("v") != 1:
        raise ValueError("Unsupported hybrid container version")
    if obj.get("alg") != HYBRID_ALGO:
        raise ValueError("Hybrid container alg mismatch")

    kid = obj.get("kid")
    if not isinstance(kid, str) or not kid:
        raise ValueError("Hybrid container kid must be non-empty string")

    ml = obj.get("ml_dsa")
    fa = obj.get("falcon")
    if not isinstance(ml, dict) or not isinstance(fa, dict):
        raise ValueError("Hybrid container components must be objects")

    ml_pub = ml.get("public_key")
    fa_pub = fa.get("public_key")
    if not isinstance(ml_pub, str) or not _is_b64(ml_pub):
        raise ValueError("Hybrid container ml_dsa public_key invalid")
    if not isinstance(fa_pub, str) or not _is_b64(fa_pub):
        raise ValueError("Hybrid container falcon public_key invalid")

    ml_sec = ml.get("secret_key")
    fa_sec = fa.get("secret_key")
    if ml_sec is not None and (not isinstance(ml_sec, str) or not _is_b64(ml_sec)):
        raise ValueError("Hybrid container ml_dsa secret_key invalid")
    if fa_sec is not None and (not isinstance(fa_sec, str) or not _is_b64(fa_sec)):
        raise ValueError("Hybrid container falcon secret_key invalid")

    return HybridKeyContainer(
        v=1,
        alg=HYBRID_ALGO,
        kid=kid,
        ml_dsa=HybridComponent(public_key=ml_pub, secret_key=ml_sec),
        falcon=HybridComponent(public_key=fa_pub, secret_key=fa_sec),
    )


def public_view_dict(container: Union[str, HybridKeyContainer]) -> Dict[str, Any]:
    """
    Return a public-only dict view of the container (NO secret keys).

    Tests expect this helper.
    Accepts either:
      - base64 container string
      - HybridKeyContainer object
    """
    c = decode_container(container) if isinstance(container, str) else container
    return {
        "v": c.v,
        "alg": c.alg,
        "kid": c.kid,
        "ml_dsa": {"public_key": c.ml_dsa.public_key},
        "falcon": {"public_key": c.falcon.public_key},
    }


def compute_container_hash(b64: str) -> str:
    """
    Compute stable SHA-256 hash over canonical JSON bytes of a VALID container.
    Returns hex string.
    """
    c = decode_container(b64)
    d = {
        "v": c.v,
        "alg": c.alg,
        "kid": c.kid,
        "ml_dsa": {"public_key": c.ml_dsa.public_key, "secret_key": c.ml_dsa.secret_key},
        "falcon": {"public_key": c.falcon.public_key, "secret_key": c.falcon.secret_key},
    }
    return hashlib.sha256(_canonical_json(d)).hexdigest()

def public_view_dict(container: HybridKeyContainer) -> dict:
    """
    Return a public-only dict view of the hybrid container.
    Secret key material is excluded.
    """
    return {
        "v": container.v,
        "alg": container.alg,
        "ml_dsa": {
            "public_key": container.ml_dsa.public_key,
        },
        "falcon": {
            "public_key": container.falcon.public_key,
        },
        "container_hash": compute_container_hash(container),
    }
