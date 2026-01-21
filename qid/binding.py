from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, TypedDict, Literal

from qid.crypto import QIDKeyPair, sign_payload, verify_payload

BindingPolicy = Literal["ml-dsa", "falcon", "hybrid"]


class BindingPayload(TypedDict, total=False):
    version: str
    type: str
    domain: str
    address: str
    policy: BindingPolicy
    pqc_pubkeys: Dict[str, Optional[str]]  # base64url strings or None
    created_at: int
    expires_at: Optional[int]


class BindingEnvelope(TypedDict, total=False):
    binding_id: str
    payload: BindingPayload
    sig: str


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _canonical_json(obj: Mapping[str, Any]) -> bytes:
    # Deterministic JSON used across the repo (same settings as qid.crypto).
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def normalize_domain(domain: str) -> str:
    """
    Domain normalization rule (v1):
    - lowercase
    - trimmed
    - reject scheme/path to avoid ambiguity (fail-closed)
    """
    if not isinstance(domain, str):
        raise TypeError("domain must be a string")
    d = domain.strip().lower()
    if not d:
        raise ValueError("domain must be non-empty")
    if "://" in d or "/" in d:
        raise ValueError("domain must not include scheme or path")
    return d


def compute_binding_id(payload: Mapping[str, Any]) -> str:
    """
    Deterministic binding id:
    binding_id = base64url( sha256( canonical_json(payload) ) )
    """
    h = hashlib.sha256(_canonical_json(payload)).digest()
    return _b64url_encode(h)


def validate_binding_payload(payload: Mapping[str, Any]) -> None:
    """
    Fail-closed validation for binding payload.
    Raises ValueError/TypeError on invalid input.
    """
    if not isinstance(payload, Mapping):
        raise TypeError("binding payload must be a mapping")

    if payload.get("version") != "1":
        raise ValueError("binding payload version must be '1'")

    if payload.get("type") != "binding":
        raise ValueError("binding payload type must be 'binding'")

    domain = payload.get("domain")
    address = payload.get("address")
    policy = payload.get("policy")
    pqc = payload.get("pqc_pubkeys")
    created_at = payload.get("created_at")
    expires_at = payload.get("expires_at", None)

    if not isinstance(domain, str):
        raise TypeError("binding payload 'domain' must be a string")
    _ = normalize_domain(domain)

    if not isinstance(address, str) or not address:
        raise ValueError("binding payload 'address' must be a non-empty string")

    if policy not in {"ml-dsa", "falcon", "hybrid"}:
        raise ValueError("binding payload 'policy' must be 'ml-dsa', 'falcon', or 'hybrid'")

    if not isinstance(pqc, dict):
        raise TypeError("binding payload 'pqc_pubkeys' must be an object")

    ml = pqc.get("ml_dsa")
    fa = pqc.get("falcon")

    # Allow None for unused key slots depending on policy.
    if policy == "ml-dsa" and not isinstance(ml, str):
        raise ValueError("policy 'ml-dsa' requires pqc_pubkeys.ml_dsa")
    if policy == "falcon" and not isinstance(fa, str):
        raise ValueError("policy 'falcon' requires pqc_pubkeys.falcon")
    if policy == "hybrid":
        if not isinstance(ml, str) or not isinstance(fa, str):
            raise ValueError("policy 'hybrid' requires both pqc_pubkeys.ml_dsa and pqc_pubkeys.falcon")

    if not isinstance(created_at, int):
        raise TypeError("binding payload 'created_at' must be an int")

    if expires_at is not None and not isinstance(expires_at, int):
        raise TypeError("binding payload 'expires_at' must be an int or null")


def build_binding_payload(
    *,
    domain: str,
    address: str,
    policy: BindingPolicy,
    ml_dsa_pub_b64u: Optional[str],
    falcon_pub_b64u: Optional[str],
    created_at: int,
    expires_at: Optional[int] = None,
) -> BindingPayload:
    d = normalize_domain(domain)

    payload: BindingPayload = {
        "version": "1",
        "type": "binding",
        "domain": d,
        "address": address,
        "policy": policy,
        "pqc_pubkeys": {
            "ml_dsa": ml_dsa_pub_b64u,
            "falcon": falcon_pub_b64u,
        },
        "created_at": created_at,
        "expires_at": expires_at,
    }

    validate_binding_payload(payload)
    return payload


def sign_binding(payload: BindingPayload, keypair: QIDKeyPair) -> BindingEnvelope:
    """
    Sign binding payload using existing Q-ID signing (same keypair class used for login).
    This is the long-term “binding statement” signature.

    NOTE: Today keypair may be dev-hmac; later can be true ECDSA without changing this API.
    """
    validate_binding_payload(payload)
    sig = sign_payload(dict(payload), keypair)
    bid = compute_binding_id(payload)
    return {"binding_id": bid, "payload": payload, "sig": sig}


def verify_binding(
    envelope: Mapping[str, Any],
    keypair: QIDKeyPair,
    *,
    expected_domain: str,
    now: Optional[int] = None,
) -> bool:
    """
    Verify binding envelope fail-closed.

    Checks:
    - binding_id matches payload hash
    - domain matches expected_domain (normalized)
    - expiry (if present)
    - signature verifies over payload
    """
    try:
        if not isinstance(envelope, Mapping):
            return False

        payload = envelope.get("payload")
        sig = envelope.get("sig")
        bid = envelope.get("binding_id")

        if not isinstance(payload, Mapping) or not isinstance(sig, str) or not isinstance(bid, str):
            return False

        validate_binding_payload(payload)

        # binding_id must match payload hash
        if bid != compute_binding_id(payload):
            return False

        # domain must match expected
        if normalize_domain(payload["domain"]) != normalize_domain(expected_domain):
            return False

        # expiry check if set
        exp = payload.get("expires_at", None)
        if exp is not None:
            if now is None:
                now = int(time.time())
            if int(now) > int(exp):
                return False

        # signature must verify over payload
        return bool(verify_payload(dict(payload), sig, keypair))
    except Exception:
        return False
