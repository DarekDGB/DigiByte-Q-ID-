from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple

from ..protocol import (
    build_login_request_payload,
    build_login_request_uri,
    parse_login_request_uri,
    build_login_response_payload,
    server_verify_login_response,
)
from ..crypto import QIDKeyPair, sign_payload


@dataclass
class QIDServiceConfig:
    """
    Simple configuration for a Q-ID relying party (service / website).

    - service_id: stable identifier for the service
    - callback_url: HTTPS endpoint that receives Q-ID login responses
    """

    service_id: str
    callback_url: str


def build_qid_login_uri(
    service: QIDServiceConfig,
    nonce: str,
    version: str = "1",
) -> str:
    """
    Build a qid://login URI for a given service + nonce.

    This is what a service would show as a QR code or deep-link for
    "Login with DigiByte Q-ID".
    """
    payload = build_login_request_payload(
        service_id=service.service_id,
        nonce=nonce,
        callback_url=service.callback_url,
        version=version,
    )
    return build_login_request_uri(payload)


def prepare_signed_login_response(
    service: QIDServiceConfig,
    login_uri: str,
    address: str,
    keypair: QIDKeyPair,
    key_id: str | None = None,
    version: str = "1",
) -> Tuple[Dict[str, Any], str]:
    """
    Wallet-side helper: parse a login URI and produce a signed response.

    Steps:
    1. Decode the login request URI.
    2. Ensure service_id + callback_url match the expected service.
    3. Build a login response payload using the wallet's address + key.
    4. Sign the payload with the selected keypair.

    Returns (response_payload, signature).
    """
    request_payload = parse_login_request_uri(login_uri)

    # Basic safety checks so the wallet is not tricked into signing for
    # the wrong service.
    if request_payload.get("service_id") != service.service_id:
        raise ValueError("Q-ID login URI service_id does not match expected service.")
    if request_payload.get("callback_url") != service.callback_url:
        raise ValueError("Q-ID login URI callback_url does not match expected service.")

    response_payload = build_login_response_payload(
        request_payload=request_payload,
        address=address,
        pubkey=keypair.public_key,
        key_id=key_id,
        version=version,
    )

    signature = sign_payload(response_payload, keypair)
    return response_payload, signature


def verify_signed_login_response_server(
    service: QIDServiceConfig,
    login_uri: str,
    response_payload: Dict[str, Any],
    signature: str,
    keypair: QIDKeyPair,
) -> bool:
    """
    Reference server-side verification flow for a signed Q-ID login.

    This helper is what a backend / service could call after receiving a
    login response from Adamantine.

    It performs:
    - decoding of the original login URI
    - service_id + callback_url matching
    - cryptographic verification via server_verify_login_response()
    """
    try:
        request_payload = parse_login_request_uri(login_uri)
    except Exception:
        return False

    if request_payload.get("service_id") != service.service_id:
        return False
    if request_payload.get("callback_url") != service.callback_url:
        return False

    return server_verify_login_response(
        request_payload=request_payload,
        response_payload=response_payload,
        signature=signature,
        keypair=keypair,
    )
