from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from qid.crypto import QIDKeyPair, sign_payload, verify_payload


# ---------------------------------------------------------------------------
# Payload builders (backward-compatible API used by tests + integrations)
# ---------------------------------------------------------------------------

def build_login_request_payload(
    *,
    service_id: str,
    nonce: str,
    callback: str | None = None,
    version: int = 1,
) -> Dict[str, Any]:
    """
    Build a deterministic login request payload.

    This mirrors Digi-ID style flows but is Q-ID oriented.
    """
    p: Dict[str, Any] = {
        "type": "login_request",
        "v": version,
        "service_id": service_id,
        "nonce": nonce,
    }
    if callback is not None:
        p["callback"] = callback
    return p


def build_login_response_payload(
    *,
    service_id: str,
    nonce: str,
    wallet_id: str,
    approved: bool,
    version: int = 1,
) -> Dict[str, Any]:
    """
    Build a deterministic login response payload.
    """
    return {
        "type": "login_response",
        "v": version,
        "service_id": service_id,
        "nonce": nonce,
        "wallet_id": wallet_id,
        "approved": bool(approved),
    }


def build_registration_payload(
    *,
    service_id: str,
    wallet_id: str,
    public_key: str,
    version: int = 1,
) -> Dict[str, Any]:
    """
    Build a deterministic registration payload.
    """
    return {
        "type": "registration",
        "v": version,
        "service_id": service_id,
        "wallet_id": wallet_id,
        "public_key": public_key,
    }


# ---------------------------------------------------------------------------
# Signed message wrapper (new API)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SignedMessage:
    """
    Signed protocol message.

    - payload: JSON-safe dict
    - signature: crypto envelope v1 (base64(canonical_json(envelope)))
    - algorithm: keypair.algorithm as protocol-visible string
    - hybrid_container_b64: optional; required only for HYBRID real-backend usage
    """
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
    Sign payload and return a SignedMessage.

    Fail-closed:
    - If crypto layer requires hybrid_container_b64, caller must supply it.
    """
    sig = sign_payload(payload, keypair, hybrid_container_b64=hybrid_container_b64)
    return SignedMessage(
        payload=payload,
        signature=sig,
        algorithm=keypair.algorithm,
        hybrid_container_b64=hybrid_container_b64,
    )


def verify_message(msg: SignedMessage, keypair: QIDKeyPair) -> bool:
    """
    Verify a SignedMessage.

    Fail-closed:
    - Any mismatch or missing required container -> False.
    """
    return verify_payload(
        msg.payload,
        msg.signature,
        keypair,
        hybrid_container_b64=msg.hybrid_container_b64,
    )
