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

- Signed login response:
    - build_login_response_payload(...)
    - sign_login_response(...)
    - verify_login_response(...)
    - server_verify_login_response(...)

These helpers focus on shaping JSON payloads and wrapping/unwrapping
them into simple qid:// URIs. Cryptography, signatures, storage and
policy checks will be added later.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict

from .qr_payloads import encode_login_request, decode_login_request
from .crypto import QIDKeyPair, sign_payload, verify_payload


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
# Signed login response helpers
# ---------------------------------------------------------------------------


def build_login_response_payload(
    request_payload: Dict[str, Any],
    address: str,
    pubkey: str,
    key_id: str | None = None,
    version: str = "1",
) -> Dict[str, Any]:
    """
    Build a Q-ID login response payload that a wallet would sign.

    This mirrors the service_id and nonce from the original login request
    and attaches the wallet's address / public key information.

    Parameters
    ----------
    request_payload:
        The decoded login request payload (output of parse_login_request_uri).
    address:
        DigiByte address controlled by the wallet.
    pubkey:
        Public key (or dev public identifier) corresponding to the signing key.
    key_id:
        Optional key identifier for rotation / multi-key setups.
    version:
        Protocol version string (default "1").
    """
    service_id = request_payload.get("service_id")
    nonce = request_payload.get("nonce")

    if not service_id or not nonce:
        raise ValueError("Login request payload must contain 'service_id' and 'nonce'.")

    payload: Dict[str, Any] = {
        "type": "login_response",
        "service_id": service_id,
        "nonce": nonce,
        "address": address,
        "pubkey": pubkey,
        "version": version,
    }
    if key_id is not None:
        payload["key_id"] = key_id
    return payload


def sign_login_response(payload: Dict[str, Any], keypair: QIDKeyPair) -> str:
    """
    Sign a login response payload using the dev crypto backend.

    In this dev implementation we delegate to qid.crypto.sign_payload,
    which uses HMAC-SHA256 over canonical JSON. Production deployments
    are expected to replace the backend with ML-DSA / hybrid schemes,
    keeping this helper's signature stable.
    """
    return sign_payload(payload, keypair)


def verify_login_response(
    payload: Dict[str, Any],
    signature: str,
    keypair: QIDKeyPair,
) -> bool:
    """
    Verify a signed login response payload with the given keypair.

    NOTE: For the dev backend this uses the same symmetric key for
    signing and verification. In a real public-key design the server
    would verify using only a public key.
    """
    return verify_payload(payload, signature, keypair)


def server_verify_login_response(
    request_payload: Dict[str, Any],
    response_payload: Dict[str, Any],
    signature: str,
    keypair: QIDKeyPair,
) -> bool:
    """
    Reference server-side verification flow for a signed login response.

    This helper performs:
    - basic shape checks (type, service_id, nonce)
    - matching of service_id + nonce between request and response
    - cryptographic signature verification via verify_login_response()
    """
    if response_payload.get("type") != "login_response":
        return False

    # service_id and nonce must match the original request
    if response_payload.get("service_id") != request_payload.get("service_id"):
        return False
    if response_payload.get("nonce") != request_payload.get("nonce"):
        return False

    # Delegate to crypto verification
    return verify_login_response(response_payload, signature, keypair)


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
