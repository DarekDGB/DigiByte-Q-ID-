"""
Hybrid Key Container v1 (contract-locked).

Contract file:
- docs/CONTRACTS/hybrid_key_container_v1.md

Goals:
- Deterministic canonical JSON
- container_hash computed from PUBLIC VIEW only (no secret_key)
- Fail-closed parsing/validation
- CI-safe (no oqs/liboqs required)
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from qid.crypto import FALCON_ALGO, HYBRID_ALGO, ML_DSA_ALGO


_CONTAINER_VERSION = 1


@dataclass(frozen=True)
class HybridKeyComponent:
    alg: str
    public_key: str
    secret_key: Optional[str] = None


@dataclass(frozen=True)
class HybridKeyContainer:
    v: int
    alg: str
    kid: str
    ml_dsa: HybridKeyComponent
    falcon: HybridKeyComponent
    container_hash: str


def _canonical_json(data: Mapping[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64decode(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _is_nonempty_str(x: Any) -> bool:
    return isinstance(x, str) and x.strip() != ""


def public_view_dict(obj: HybridKeyContainer | Dict[str, Any]) -> Dict[str, Any]:
    """
    Public view used for container_hash:
      - v, alg, kid
      - ml_dsa.alg, ml_dsa.public_key
      - falcon.alg, falcon.public_key
    """
    if isinstance(obj, HybridKeyContainer):
        v = obj.v
        alg = obj.alg
        kid = obj.kid
        ml = {"alg": obj.ml_dsa.alg, "public_key": obj.ml_dsa.public_key}
        fa = {"alg": obj.falcon.alg, "public_key": obj.falcon.public_key}
    else:
        v = obj.get("v")
        alg = obj.get("alg")
        kid = obj.get("kid")
        ml_dsa = obj.get("ml_dsa") or {}
        falcon = obj.get("falcon") or {}
        ml = {"alg": ml_dsa.get("alg"), "public_key": ml_dsa.get("public_key")}
        fa = {"alg": falcon.get("alg"), "public_key": falcon.get("public_key")}

    return {"v": v, "alg": alg, "kid": kid, "ml_dsa": ml, "falcon": fa}


def compute_container_hash(obj: HybridKeyContainer | Dict[str, Any]) -> str:
    """
    container_hash = base64( sha256( canonical_json(public_view) ) )
    """
    pv = public_view_dict(obj)
    digest = hashlib.sha256(_canonical_json(pv)).digest()
    return _b64encode(digest)


def validate_container_dict(d: Mapping[str, Any]) -> None:
    """
    Validate container dict against contract invariants.
    Raises ValueError on any mismatch (fail-closed).
    """
    if d.get("v") != _CONTAINER_VERSION:
        raise ValueError("Invalid container version")

    if d.get("alg") != HYBRID_ALGO:
        raise ValueError("Invalid container alg")

    kid = d.get("kid")
    if not _is_nonempty_str(kid):
        raise ValueError("Invalid kid")

    ml = d.get("ml_dsa")
    fa = d.get("falcon")
    if not isinstance(ml, dict) or not isinstance(fa, dict):
        raise ValueError("Invalid component objects")

    if ml.get("alg") != ML_DSA_ALGO:
        raise ValueError("Invalid ml_dsa alg")
    if fa.get("alg") != FALCON_ALGO:
        raise ValueError("Invalid falcon alg")

    if not _is_nonempty_str(ml.get("public_key")):
        raise ValueError("Missing ml_dsa public_key")
    if not _is_nonempty_str(fa.get("public_key")):
        raise ValueError("Missing falcon public_key")

    # container_hash must exist and match recomputation from public view
    ch = d.get("container_hash")
    if not _is_nonempty_str(ch):
        raise ValueError("Missing container_hash")

    expected = compute_container_hash(d)
    if ch != expected:
        raise ValueError("container_hash mismatch")

    # Optional secret_key fields must be strings if present
    if "secret_key" in ml and ml["secret_key"] is not None and not isinstance(ml["secret_key"], str):
        raise ValueError("Invalid ml_dsa secret_key")
    if "secret_key" in fa and fa["secret_key"] is not None and not isinstance(fa["secret_key"], str):
        raise ValueError("Invalid falcon secret_key")


def to_dict(container: HybridKeyContainer) -> Dict[str, Any]:
    return {
        "v": container.v,
        "alg": container.alg,
        "kid": container.kid,
        "ml_dsa": {
            "alg": container.ml_dsa.alg,
            "public_key": container.ml_dsa.public_key,
            **({} if container.ml_dsa.secret_key is None else {"secret_key": container.ml_dsa.secret_key}),
        },
        "falcon": {
            "alg": container.falcon.alg,
            "public_key": container.falcon.public_key,
            **({} if container.falcon.secret_key is None else {"secret_key": container.falcon.secret_key}),
        },
        "container_hash": container.container_hash,
    }


def from_dict(d: Mapping[str, Any]) -> HybridKeyContainer:
    validate_container_dict(d)

    ml = d["ml_dsa"]
    fa = d["falcon"]

    ml_comp = HybridKeyComponent(
        alg=ml["alg"],
        public_key=ml["public_key"],
        secret_key=ml.get("secret_key"),
    )
    fa_comp = HybridKeyComponent(
        alg=fa["alg"],
        public_key=fa["public_key"],
        secret_key=fa.get("secret_key"),
    )

    return HybridKeyContainer(
        v=d["v"],
        alg=d["alg"],
        kid=d["kid"],
        ml_dsa=ml_comp,
        falcon=fa_comp,
        container_hash=d["container_hash"],
    )


def encode_container(d: Mapping[str, Any] | HybridKeyContainer) -> str:
    """
    Encode as base64(canonical_json(container)).
    """
    obj = to_dict(d) if isinstance(d, HybridKeyContainer) else dict(d)
    # Fail-closed: only encode valid containers
    validate_container_dict(obj)
    return _b64encode(_canonical_json(obj))


def decode_container(s: str) -> HybridKeyContainer:
    """
    Decode base64(JSON) and validate.
    Raises ValueError on any failure.
    """
    raw = _b64decode(s)
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Container must decode to object")
    return from_dict(data)


def try_decode_container(s: str) -> HybridKeyContainer | None:
    """
    Fail-closed helper: returns None on any decode/validation error.
    """
    try:
        return decode_container(s)
    except Exception:
        return None


def build_container(
    kid: str,
    ml_dsa_public_key: str,
    falcon_public_key: str,
    ml_dsa_secret_key: str | None = None,
    falcon_secret_key: str | None = None,
) -> HybridKeyContainer:
    """
    Construct a container and compute container_hash (public-view only).
    """
    obj: Dict[str, Any] = {
        "v": _CONTAINER_VERSION,
        "alg": HYBRID_ALGO,
        "kid": kid,
        "ml_dsa": {"alg": ML_DSA_ALGO, "public_key": ml_dsa_public_key},
        "falcon": {"alg": FALCON_ALGO, "public_key": falcon_public_key},
    }
    if ml_dsa_secret_key is not None:
        obj["ml_dsa"]["secret_key"] = ml_dsa_secret_key
    if falcon_secret_key is not None:
        obj["falcon"]["secret_key"] = falcon_secret_key

    obj["container_hash"] = compute_container_hash(obj)
    return from_dict(obj)
