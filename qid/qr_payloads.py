"""
QR payload handling for DigiByte Q-ID.

This module is intentionally thin.

All URI encoding/decoding rules live in:
    qid/uri_scheme.py

We keep these wrappers to preserve the earlier public API used by tests and
integrations.

Login URI format:
    qid://login?d=<base64url(JSON)>

Decoded JSON object (login request):
{
  "type": "login_request",
  "service_id": "example.com",
  "nonce": "random-unique-string",
  "callback_url": "https://example.com/qid/callback",
  "version": "1"
}
"""

from __future__ import annotations

from typing import Any, Dict

from .uri_scheme import decode_login_request as decode_login_request
from .uri_scheme import encode_login_request as encode_login_request


def encode_login_request_uri(payload: Dict[str, Any]) -> str:
    """
    Backwards compatible wrapper (older code used *_uri suffix).
    """
    return encode_login_request(payload)


def decode_login_request_uri(uri: str) -> Dict[str, Any]:
    """
    Backwards compatible wrapper (older code used *_uri suffix).
    """
    return decode_login_request(uri)
