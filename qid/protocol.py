"""
MIT License
Copyright (c) 2025 DarekDGB

High-level DigiByte Q-ID protocol helpers.

Provides helpers for:
- login request payloads + qid:// login URIs
- login responses + signing/verification flows
- registration payloads + qid:// register URIs
- SignedMessage wrapper used by tests

Fail-closed + CI-safe rules:
- sign_message() MUST NOT raise for expected user/config errors (e.g. hybrid container missing
  when required). It returns a SignedMessage that will fail verification (fail-closed).
- Programming errors should not be silently swallowed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from .crypto import QIDKeyPair, sign_payload, verify_payload
from .errors import QIDError
from .uri_scheme import (
    decode_login_request_uri,
    decode_registration_uri,
    encode_login_request_uri,
    encode_registration_uri,
)

# ---------------------------------------------------------------------------
# SignedMessage wrapper (used by tests)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignedMessage:
    payload: Dict[str, Any]
    signature: str
    algorithm: str
    hybrid_container_b64: Optional[str] = None


def sign_message(
    payload: Dict[str, Any],
    keypair: QIDKeyPair,
    *,
    hybrid_container_b64: Optional[str] = None,
) -> SignedMessage:
    """
    Sign an arbitrary protocol payload and return a SignedMessage.

    Fail-closed policy:
    - For expected validation/config errors (ValueError/TypeError/QIDError),
      do not raise from the protocol layer. Return an empty signature so
      verification fails closed.
    - Do NOT blanket-catch all exceptions; programmer bugs must surface.
    """
    try:
        sig = sign_payload(payload, keypair, hybrid_container_b64=hybrid_container_b64)
    except (ValueError, TypeError, QIDError):
        sig = ""  # fail-closed without crashing protocol layer

    return SignedMessage(
        payload=payload,
        signature=sig,
        algorithm=keypair.algorithm,
        hybrid_container_b64=hybrid_container_b64,
    )


def verify_message(msg: SignedMessage, keypair: QIDKeyPair) -> bool:
    """Verify a SignedMessage. Fail-closed on any mismatch or parsing error."""
    return verify_payload(
        msg.payload,
        msg.signature,
        keypair,
        hybrid_container_b64=msg.hybrid_container_b64,
    )


# ---------------------------------------------------------------------------
# Login helpers
# ---------------------------------------------------------------------------


def build_login_request_payload(
    service_id: str,
    nonce: str,
    callback_url: str,
    version: str = "1",
) -> Dict[str, Any]:
    return {
        "type": "login_request",
        "service_id": service_id,
        "nonce": nonce,
        "callback_url": callback_url,
        "version": version,
    }


def build_login_request_uri(payload: Dict[str, Any]) -> str:
    return encode_login_request_uri(payload)


def parse_login_request_uri(uri: str) -> Dict[str, Any]:
    return decode_login_request_uri(uri)


def build_login_response_payload(
    request_payload: Dict[str, Any],
    address: str,
    pubkey: str,
    key_id: str | None = None,
    version: str = "1",
) -> Dict[str, Any]:
    service_id = request_payload.get("service_id")
    nonce = request_payload.get("nonce")
    if not isinstance(service_id, str) or not service_id:
        raise ValueError("Login request payload must contain non-empty 'service_id'.")
    if not isinstance(nonce, str) or not nonce:
        raise ValueError("Login request payload must contain non-empty 'nonce'.")

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


def sign_login_response(
    payload: Dict[str, Any],
    keypair: QIDKeyPair,
    *,
    hybrid_container_b64: Optional[str] = None,
) -> str:
    return sign_payload(payload, keypair, hybrid_container_b64=hybrid_container_b64)


def verify_login_response(
    payload: Dict[str, Any],
    signature: str,
    keypair: QIDKeyPair,
    *,
    hybrid_container_b64: Optional[str] = None,
) -> bool:
    return verify_payload(payload, signature, keypair, hybrid_container_b64=hybrid_container_b64)


def server_verify_login_response(
    request_payload: Dict[str, Any],
    response_payload: Dict[str, Any],
    signature: str,
    keypair: QIDKeyPair,
    *,
    hybrid_container_b64: Optional[str] = None,
) -> bool:
    if response_payload.get("type") != "login_response":
        return False
    if response_payload.get("service_id") != request_payload.get("service_id"):
        return False
    if response_payload.get("nonce") != request_payload.get("nonce"):
        return False
    return verify_login_response(
        response_payload,
        signature,
        keypair,
        hybrid_container_b64=hybrid_container_b64,
    )


def login(
    service_id: str,
    callback_url: str,
    nonce: str,
    *,
    address: str,
    pubkey: str,
    keypair: QIDKeyPair,
    version: str = "1",
    key_id: str | None = None,
    hybrid_container_b64: Optional[str] = None,
) -> SignedMessage:
    """
    Convenience wrapper: build a login_request and signed login_response.

    This is strict-only (no legacy placeholder mode).
    """
    req = build_login_request_payload(
        service_id=service_id,
        nonce=nonce,
        callback_url=callback_url,
        version=version,
    )
    resp = build_login_response_payload(
        req,
        address=address,
        pubkey=pubkey,
        key_id=key_id,
        version=version,
    )
    return sign_message(resp, keypair, hybrid_container_b64=hybrid_container_b64)


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
    return encode_registration_uri(payload)


def parse_registration_uri(uri: str) -> Dict[str, Any]:
    return decode_registration_uri(uri)


def register_identity(
    service_id: str,
    address: str,
    pubkey: str,
    nonce: str,
    callback_url: str,
    keypair: QIDKeyPair,
    *,
    version: str = "1",
    hybrid_container_b64: Optional[str] = None,
) -> SignedMessage:
    """
    Convenience wrapper: build a registration payload and sign it.

    This is strict-only (no legacy placeholder mode).
    """
    payload = build_registration_payload(
        service_id=service_id,
        address=address,
        pubkey=pubkey,
        nonce=nonce,
        callback_url=callback_url,
        version=version,
    )
    return sign_message(payload, keypair, hybrid_container_b64=hybrid_container_b64)
