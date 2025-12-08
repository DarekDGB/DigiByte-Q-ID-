"""
High-level DigiByte Q-ID protocol helpers.

This module currently provides helpers for:

- Login request:
    - build_login_request_payload(...)
    - build_login_request_uri(...)
    - parse_login_request_uri(...)

- Registration request:
    - build_registration_payload(...)
    - build_registration_uri(...)
    - parse_registration_uri(...)

These helpers focus on shaping JSON payloads and wrapping/unwrapping
them into simple qid:// URIs. Cryptography, signatures, storage and
policy checks will be added later.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict

from .qr_payloads import encode_login_request, decode_login_request


# ---------------------------------------------------------------------------
# Shared base64url helpers (local to this module)
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    """Encode bytes to URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(token: str) -> bytes:
    """Decode URL-safe base64 without padding."""
    padding = "=" * (-len(token) % 4)
    return base64.urlsafe_b64decode(token + padding)


# ---------------------------------------------------------------------------
# Login helpers
# ---------------------------------------------------------------------------


def build_login_request_payload(
    service_id: str,
    nonce: str,
    callback_url: str,
    version: str = "1",
) -> Dict[str, Any]:
    """
    Build a minimal Q-ID login request payload.

    This does *not* handle crypto or signatures. It only shapes the JSON
    that will be embedded into the qid:// URI.
    """
    return {
        "type": "login_request",
        "service_id": service_id,
        "nonce": nonce,
        "callback_url": callback_url,
        "version": version,
    }


def build_login_request_uri(payload: Dict[str, Any]) -> str:
    """
    Convert a login payload into a qid:// URI using the QR encoder.
    """
    return encode_login_request(payload)


def parse_login_request_uri(uri: str) -> Dict[str, Any]:
    """
    Decode a qid://login URI back into a login payload dictionary.
    """
    return decode_login_request(uri)


# ---------------------------------------------------------------------------
# Registration helpers
# ---------------------------------------------------------------------------


def build_registration_payload(
    service_id: str,
    address: str,
    pubkey: str,
    nonce: str,
    callback_url: str,
    version: str = "1",
) -> Dict[str, Any]:
    """
    Build a Q-ID registration payload.

    This links:
    - a DigiByte address
    - a (possibly quantum-safe) public key
    - a specific service identifier
    """
    return {
        "type": "registration",
        "service_id": service_id,
        "address": address,
        "pubkey": pubkey,
        "nonce": nonce,
        "callback_url": callback_url,
        "version": version,
    }


def build_registration_uri(payload: Dict[str, Any]) -> str:
    """
    Encode a registration payload into a qid://register URI.

    Format:
        qid://register?d=<base64url(JSON)>
    """
    json_str = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    token = _b64url_encode(json_str.encode("utf-8"))
    return f"qid://register?d={token}"


def parse_registration_uri(uri: str) -> Dict[str, Any]:
    """
    Decode a qid://register?d=... URI back into a registration payload dict.
    """
    prefix = "qid://"
    if not uri.startswith(prefix):
        raise ValueError("Not a Q-ID URI (missing 'qid://' prefix).")

    rest = uri[len(prefix) :]  # e.g. "register?d=abc"
    if "?" not in rest:
        raise ValueError("Q-ID URI missing query part.")
    action, query = rest.split("?", 1)

    if action != "register":
        raise ValueError(f"Unsupported Q-ID action for registration: {action!r}")

    token = None
    for pair in query.split("&"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        if key == "d":
            token = value
            break

    if token is None:
        raise ValueError("Q-ID registration URI missing 'd' parameter.")

    try:
        data_bytes = _b64url_decode(token)
        payload = json.loads(data_bytes.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Failed to decode Q-ID registration payload.") from exc

    if not isinstance(payload, dict):
        raise ValueError("Q-ID registration payload must be a JSON object.")

    return payload


# ---------------------------------------------------------------------------
# Placeholders for future full protocol flows
# ---------------------------------------------------------------------------


def register_identity(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Placeholder registration flow.

    In the future this will:
    - bind a Q-ID identity to a service
    - create QIDCredential objects
    - coordinate with crypto + storage layers
    """
    return {"status": "todo", "detail": "Q-ID registration not implemented yet."}


def login(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Placeholder login flow.

    In the future this will:
    - verify signatures from the wallet
    - look up the corresponding QIDCredential
    - apply policy / trust checks
    """
    return {"status": "todo", "detail": "Q-ID login not implemented yet."}
