"""
MIT License
Copyright (c) 2025 DarekDGB
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import json
from typing import Any, Dict, Mapping, Optional, Union, cast

from .crypto import FALCON_ALGO, HYBRID_ALGO, ML_DSA_ALGO


_CONTAINER_VERSION = 1


# -------------------------
# helpers (deterministic)
# -------------------------


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64u_decode(s: str) -> bytes:
    # fail-closed: reject non-str / empty / bad padding
    if not isinstance(s, str) or not s:
        raise ValueError("Invalid base64url string")
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _is_non_empty_str(x: Any) -> bool:
    return isinstance(x, str) and x.strip() != ""


# -------------------------
# datamodel
# -------------------------


@dataclass(frozen=True)
class KeyComponent:
    alg: str
    public_key: str
    secret_key: Optional[str] = None


@dataclass(frozen=True)
class HybridKeyContainer:
    v: int
    alg: str
    kid: str
    ml_dsa: KeyComponent
    falcon: KeyComponent
    container_hash: str


# -------------------------
# public view + hash
# -------------------------


def public_view_dict(obj: Union[HybridKeyContainer, Mapping[str, Any], str]) -> Dict[str, Any]:
    """
    Public-only view (NO secret keys).
    Tests expect this helper to accept:
      - HybridKeyContainer
      - dict
      - base64 container string
    """
    c: Union[HybridKeyContainer, Mapping[str, Any]]
    if isinstance(obj, str):
        c = to_dict(decode_container(obj))
    else:
        c = obj

    if isinstance(c, HybridKeyContainer):
        return {
            "v": c.v,
            "alg": c.alg,
            "kid": c.kid,
            "ml_dsa": {"alg": c.ml_dsa.alg, "public_key": c.ml_dsa.public_key},
            "falcon": {"alg": c.falcon.alg, "public_key": c.falcon.public_key},
        }

    # mapping/dict path
    d = cast(Mapping[str, Any], c)
    ml = cast(Mapping[str, Any], d.get("ml_dsa") or {})
    fa = cast(Mapping[str, Any], d.get("falcon") or {})
    return {
        "v": d.get("v"),
        "alg": d.get("alg"),
        "kid": d.get("kid"),
        "ml_dsa": {"alg": ml.get("alg"), "public_key": ml.get("public_key")},
        "falcon": {"alg": fa.get("alg"), "public_key": fa.get("public_key")},
    }


def compute_container_hash(obj: Union[HybridKeyContainer, Mapping[str, Any], str]) -> str:
    """
    container_hash = base64url( sha256( canonical_json(public_view) ) )
    """
    pv = public_view_dict(obj)
    digest = hashlib.sha256(_canonical_json(pv)).digest()
    return _b64u_encode(digest)


# -------------------------
# validation / conversion
# -------------------------


def _validate_container_dict(d: Mapping[str, Any]) -> None:
    # v
    v = d.get("v")
    if v != _CONTAINER_VERSION:
        raise ValueError("Invalid container version")

    # alg
    alg = d.get("alg")
    if alg != HYBRID_ALGO:
        raise ValueError("Invalid container alg")

    # kid
    kid = d.get("kid")
    if not _is_non_empty_str(kid):
        raise ValueError("Invalid kid")

    # components
    ml = d.get("ml_dsa")
    fa = d.get("falcon")
    if not isinstance(ml, Mapping) or not isinstance(fa, Mapping):
        raise ValueError("Missing components")

    if ml.get("alg") != ML_DSA_ALGO:
        raise ValueError("ml_dsa.alg mismatch")
    if fa.get("alg") != FALCON_ALGO:
        raise ValueError("falcon.alg mismatch")

    if not _is_non_empty_str(ml.get("public_key")):
        raise ValueError("ml_dsa.public_key missing")
    if not _is_non_empty_str(fa.get("public_key")):
        raise ValueError("falcon.public_key missing")

    # container_hash required and must match computed hash from PUBLIC VIEW ONLY
    ch = d.get("container_hash")
    if not _is_non_empty_str(ch):
        raise ValueError("container_hash missing")

    expected = compute_container_hash(d)
    if ch != expected:
        raise ValueError("container_hash mismatch")


def from_dict(d: Mapping[str, Any]) -> HybridKeyContainer:
    _validate_container_dict(d)

    ml = cast(Mapping[str, Any], d["ml_dsa"])
    fa = cast(Mapping[str, Any], d["falcon"])

    # secret_key optional, but if present must be string
    ml_sk = ml.get("secret_key")
    fa_sk = fa.get("secret_key")
    if ml_sk is not None and not isinstance(ml_sk, str):
        raise ValueError("ml_dsa.secret_key wrong type")
    if fa_sk is not None and not isinstance(fa_sk, str):
        raise ValueError("falcon.secret_key wrong type")

    return HybridKeyContainer(
        v=int(d["v"]),
        alg=str(d["alg"]),
        kid=str(d["kid"]),
        ml_dsa=KeyComponent(alg=str(ml["alg"]), public_key=str(ml["public_key"]), secret_key=cast(Optional[str], ml_sk)),
        falcon=KeyComponent(alg=str(fa["alg"]), public_key=str(fa["public_key"]), secret_key=cast(Optional[str], fa_sk)),
        container_hash=str(d["container_hash"]),
    )


def to_dict(c: HybridKeyContainer) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "v": c.v,
        "alg": c.alg,
        "kid": c.kid,
        "ml_dsa": {"alg": c.ml_dsa.alg, "public_key": c.ml_dsa.public_key},
        "falcon": {"alg": c.falcon.alg, "public_key": c.falcon.public_key},
        "container_hash": c.container_hash,
    }
    if c.ml_dsa.secret_key is not None:
        d["ml_dsa"]["secret_key"] = c.ml_dsa.secret_key
    if c.falcon.secret_key is not None:
        d["falcon"]["secret_key"] = c.falcon.secret_key
    return d


# -------------------------
# encode/decode
# -------------------------


def encode_container(container: Union[HybridKeyContainer, Mapping[str, Any]]) -> str:
    """
    Encode container dict/object as base64url(canonical_json(container_dict)).
    Must validate and enforce correct container_hash.
    """
    if isinstance(container, HybridKeyContainer):
        d = to_dict(container)
    else:
        d = dict(container)

    # validate AND enforce hash matches public view
    _validate_container_dict(d)

    return _b64u_encode(_canonical_json(d))


def decode_container(b64: str) -> HybridKeyContainer:
    """
    Decode base64url JSON container and validate strictly.
    """
    raw = _b64u_decode(b64)
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise ValueError("Invalid container JSON") from e

    if not isinstance(obj, dict):
        raise ValueError("Container JSON must be an object")

    return from_dict(cast(Mapping[str, Any], obj))


def try_decode_container(x: Union[str, HybridKeyContainer, Mapping[str, Any]]) -> Optional[HybridKeyContainer]:
    """
    Fail-closed helper:
      - returns HybridKeyContainer on success
      - returns None on any error
    Accepts base64 string OR object OR dict.
    """
    try:
        if isinstance(x, HybridKeyContainer):
            # validate via encode/decode invariants
            _validate_container_dict(to_dict(x))
            return x
        if isinstance(x, Mapping):
            return from_dict(x)
        return decode_container(x)
    except Exception:
        return None


# -------------------------
# build_container (test-shaped)
# -------------------------


def build_container(*args: Any, **kwargs: Any) -> HybridKeyContainer:
    """
    Build container in the TWO styles tests use:

    Style A (positional):
      build_container(kid, ml_dsa_public_key, falcon_public_key, ml_dsa_secret_key=None, falcon_secret_key=None)

    Style B (keyword alt names):
      build_container(alg=HYBRID_ALGO, ml_dsa_pub=..., falcon_pub=..., kid="kid")

    Also supports explicit keyword names:
      kid=..., ml_dsa_public_key=..., falcon_public_key=...
    """
    # Style A positional
    if args:
        if len(args) not in (3, 4, 5):
            raise TypeError("build_container(): expected 3-5 positional args")
        kid = args[0]
        ml_pub = args[1]
        fa_pub = args[2]
        ml_sk = args[3] if len(args) >= 4 else None
        fa_sk = args[4] if len(args) >= 5 else None
        alg = HYBRID_ALGO
    else:
        # Style B keywords
        alg = kwargs.pop("alg", HYBRID_ALGO)
        kid = kwargs.pop("kid", "kid")
        # accept both naming conventions
        ml_pub = kwargs.pop("ml_dsa_public_key", kwargs.pop("ml_dsa_pub", None))
        fa_pub = kwargs.pop("falcon_public_key", kwargs.pop("falcon_pub", None))
        ml_sk = kwargs.pop("ml_dsa_secret_key", None)
        fa_sk = kwargs.pop("falcon_secret_key", None)

        if kwargs:
            raise TypeError(f"build_container(): unexpected kwargs: {sorted(kwargs.keys())!r}")

    if alg != HYBRID_ALGO:
        raise ValueError("build_container(): alg must be HYBRID_ALGO")
    if not _is_non_empty_str(kid):
        raise ValueError("build_container(): kid required")
    if not _is_non_empty_str(ml_pub) or not _is_non_empty_str(fa_pub):
        raise ValueError("build_container(): public keys required")

    obj: Dict[str, Any] = {
        "v": _CONTAINER_VERSION,
        "alg": HYBRID_ALGO,
        "kid": str(kid),
        "ml_dsa": {"alg": ML_DSA_ALGO, "public_key": str(ml_pub)},
        "falcon": {"alg": FALCON_ALGO, "public_key": str(fa_pub)},
    }

    if ml_sk is not None:
        if not isinstance(ml_sk, str):
            raise ValueError("ml_dsa_secret_key wrong type")
        obj["ml_dsa"]["secret_key"] = ml_sk
    if fa_sk is not None:
        if not isinstance(fa_sk, str):
            raise ValueError("falcon_secret_key wrong type")
        obj["falcon"]["secret_key"] = fa_sk

    obj["container_hash"] = compute_container_hash(obj)
    return from_dict(obj)
