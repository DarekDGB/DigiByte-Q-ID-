"""
MIT License
Copyright (c) 2025 DarekDGB

Binding envelopes for DigiByte Q-ID.

Design goals:
- Deterministic binding_id computed from canonical payload bytes.
- Fail-closed verification: any malformed input returns False (never raises).
- Time rules:
  - created_at MUST be <= now (using provided now, else wall clock) to prevent "future-issued" bindings.
  - expires_at (if present) MUST be >= now.
- Signature rules:
  - envelope MUST contain a non-empty signature field: `sig` (preferred) or legacy `signature`.
  - signature MUST verify over the payload.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
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
    if "://" in d:
        raise ValueError("domain must not include scheme")
    if "/" in d:
        raise ValueError("domain must not include path")
    return d


def compute_binding_id(payload: BindingPayload) -> str:
    """
    Deterministic binding_id = b64url(sha256(canonical_json(payload))).
    """
    raw = _canonical_json(payload)
    h = hashlib.sha256(raw).digest()
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
    if not isinstance(domain, str) or not domain:
        raise ValueError("binding payload 'domain' must be a non-empty string")
    _ = normalize_domain(domain)

    address = payload.get("address")
    if not isinstance(address, str) or not address:
        raise ValueError("binding payload 'address' must be a non-empty string")

    policy = payload.get("policy")
    if policy not in ("ml-dsa", "falcon", "hybrid"):
        raise ValueError("binding payload 'policy' must be 'ml-dsa', 'falcon', or 'hybrid'")

    pqc = payload.get("pqc_pubkeys")
    if not isinstance(pqc, Mapping):
        raise ValueError("binding payload 'pqc_pubkeys' must be a mapping")

    ml = pqc.get("ml_dsa")
    fa = pqc.get("falcon")

    # policy gating for required keys
    if policy in ("ml-dsa", "hybrid") and not isinstance(ml, str):
        raise ValueError("binding payload requires 'pqc_pubkeys.ml_dsa' for policy ml-dsa/hybrid")
    if policy in ("falcon", "hybrid") and not isinstance(fa, str):
        raise ValueError("binding payload requires 'pqc_pubkeys.falcon' for policy falcon/hybrid")

    created_at = payload.get("created_at")
    if not isinstance(created_at, int):
        raise TypeError("binding payload 'created_at' must be an int")

    expires_at = payload.get("expires_at", None)
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
    Sign a binding payload and return a binding envelope.
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
    - required fields present (binding_id, payload, signature)
    - binding_id matches payload hash
    - domain matches expected_domain (normalized)
    - created_at <= now (using provided now else wall clock)
    - expiry (if present): now <= expires_at
    - signature verifies over payload
    """
    try:
        if not isinstance(envelope, Mapping):
            return False

        payload = envelope.get("payload")
        if not isinstance(payload, Mapping):
            return False

        bid = envelope.get("binding_id")
        if not isinstance(bid, str) or not bid:
            return False

        # Accept preferred 'sig' and legacy 'signature' (but require one of them).
        sig = envelope.get("sig")
        if sig is None:
            sig = envelope.get("signature")
        if not isinstance(sig, str) or not sig:
            return False

        # Validate payload schema first (fail-closed)
        validate_binding_payload(payload)

        # now must be int if provided
        if now is not None and not isinstance(now, int):
            return False

        now_eff = int(time.time()) if now is None else now

        created_at = payload.get("created_at")
        if not isinstance(created_at, int):
            return False
        if created_at > now_eff:
            return False

        exp = payload.get("expires_at", None)
        if exp is not None:
            if not isinstance(exp, int):
                return False
            if now_eff > exp:
                return False

        # binding_id must match payload hash
        if bid != compute_binding_id(payload):  # type: ignore[arg-type]
            return False

        # domain must match expected
        if normalize_domain(str(payload.get("domain", ""))) != normalize_domain(expected_domain):
            return False

        # signature must verify over payload
        return bool(verify_payload(dict(payload), sig, keypair))
    except Exception:
        return False
