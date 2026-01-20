"""
Q-ID URI Scheme (contract-locked).

This module is the single source of truth for qid:// URIs.

Rules:
- URL-safe base64 (no padding) for the `d=` payload parameter.
- Payload bytes MUST be UTF-8 JSON.
- Fail-closed decoding (raise ValueError).

Backwards compatibility:
Older modules/tests used function names with *_uri suffix. We provide aliases.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict


_QID_PREFIX = "qid://"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(token: str) -> bytes:
    padding = "=" * (-len(token) % 4)
    return base64.urlsafe_b64decode(token + padding)


def _extract_query_param(query: str, key: str) -> str | None:
    for pair in query.split("&"):
        if not pair:
            continue
        k, _, v = pair.partition("=")
        if k == key:
            return v
    return None


def encode_uri(action: str, payload: Dict[str, Any]) -> str:
    if not action or any(c.isspace() for c in action):
        raise ValueError("Invalid Q-ID action")

    json_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    token = _b64url_encode(json_bytes)
    return f"{_QID_PREFIX}{action}?d={token}"


def decode_uri(uri: str, *, expected_action: str | None = None) -> Dict[str, Any]:
    if not uri.startswith(_QID_PREFIX):
        raise ValueError("Not a Q-ID URI (missing 'qid://' prefix).")

    rest = uri[len(_QID_PREFIX) :]
    if "?" not in rest:
        raise ValueError("Q-ID URI missing query part.")

    action, query = rest.split("?", 1)
    if expected_action is not None and action != expected_action:
        raise ValueError(f"Unsupported Q-ID action: {action!r}")

    token = _extract_query_param(query, "d")
    if token is None:
        raise ValueError("Q-ID URI missing 'd' parameter.")

    try:
        raw = _b64url_decode(token)
        obj = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Failed to decode Q-ID payload.") from exc

    if not isinstance(obj, dict):
        raise ValueError("Q-ID payload must be a JSON object.")

    return obj


# Preferred canonical names
def encode_login_request(payload: Dict[str, Any]) -> str:
    return encode_uri("login", payload)


def decode_login_request(uri: str) -> Dict[str, Any]:
    return decode_uri(uri, expected_action="login")


def encode_registration(payload: Dict[str, Any]) -> str:
    return encode_uri("register", payload)


def decode_registration(uri: str) -> Dict[str, Any]:
    return decode_uri(uri, expected_action="register")


# Backwards-compatible aliases used by protocol/tests
def encode_login_request_uri(payload: Dict[str, Any]) -> str:
    return encode_login_request(payload)


def decode_login_request_uri(uri: str) -> Dict[str, Any]:
    return decode_login_request(uri)


def encode_registration_uri(payload: Dict[str, Any]) -> str:
    return encode_registration(payload)


def decode_registration_uri(uri: str) -> Dict[str, Any]:
    return decode_registration(uri)
