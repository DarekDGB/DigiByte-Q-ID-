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
- sign_message() MUST NOT raise for expected user/config errors. It returns a SignedMessage
  that will fail verification (fail-closed).
- Programming errors should not be silently swallowed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Mapping, MutableMapping

from .binding import verify_binding
from .crypto import QIDKeyPair, sign_payload, verify_payload
from .pqc_backends import PQCBackendError, ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO
from .pqc_sign import sign_pqc_login_fields
from .uri_scheme import (
    decode_login_request_uri,
    decode_registration_uri,
    encode_login_request_uri,
    encode_registration_uri,
)

# ---------------------------------------------------------------------------
# Require modes (v1)
# ---------------------------------------------------------------------------

REQUIRE_LEGACY = "legacy"
REQUIRE_DUAL_PROOF = "dual-proof"
_ALLOWED_REQUIRE = {REQUIRE_LEGACY, REQUIRE_DUAL_PROOF}

# Reserved, non-serialized keys for Python integration (do not put into QR/URI JSON).
_BINDING_RESOLVER_KEY = "_binding_resolver"
_NOW_KEY = "_now"


def _require_from_payload(p: Dict[str, Any]) -> str:
    """Extract and validate 'require' mode from payload. Defaults to legacy."""
    r = p.get("require", REQUIRE_LEGACY)
    if not isinstance(r, str):
        raise ValueError("'require' must be a string if present")
    r = r.strip().lower()
    if r not in _ALLOWED_REQUIRE:
        raise ValueError("'require' must be 'legacy' or 'dual-proof'")
    return r


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
    - For expected validation/config/backend errors (ValueError/TypeError/PQCBackendError),
      do not raise from the protocol layer. Return an empty signature so verification fails.
    - Do NOT blanket-catch all exceptions; programmer bugs must surface.
    """
    try:
        sig = sign_payload(payload, keypair, hybrid_container_b64=hybrid_container_b64)
    except (ValueError, TypeError, PQCBackendError):
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
        # Compatibility contract:
        # - Missing or legacy => Digi-ID compatible verification.
        # - dual-proof => verifier MUST enforce binding + PQC (later layers).
        "require": REQUIRE_LEGACY,
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

    require_mode = _require_from_payload(request_payload)

    payload: Dict[str, Any] = {
        "type": "login_response",
        "service_id": service_id,
        "nonce": nonce,
        "address": address,
        "pubkey": pubkey,
        "require": require_mode,
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
    """
    Server-side verification for login responses.

    Binding Path B (no API surface changes):
    - For require="dual-proof", the server must provide a resolver callable via:
        request_payload["_binding_resolver"] = callable(binding_id) -> binding_envelope | None
      Optional deterministic time override:
        request_payload["_now"] = int

    This keeps public signatures stable (API contract test) while enabling binding enforcement.
    """
    try:
        if response_payload.get("type") != "login_response":
            return False
        if response_payload.get("service_id") != request_payload.get("service_id"):
            return False
        if response_payload.get("nonce") != request_payload.get("nonce"):
            return False

        req_mode = _require_from_payload(request_payload)
        resp_mode = _require_from_payload(response_payload)
        if resp_mode != req_mode:
            return False

        if resp_mode == REQUIRE_DUAL_PROOF:
            binding_id = response_payload.get("binding_id")
            if not isinstance(binding_id, str):
                return False

            resolver = request_payload.get(_BINDING_RESOLVER_KEY)
            if resolver is None or not callable(resolver):
                return False

            binding_env = resolver(binding_id)
            if binding_env is None:
                return False

            now = request_payload.get(_NOW_KEY)
            if now is not None and not isinstance(now, int):
                return False

            if not verify_binding(
                binding_env,
                keypair,
                expected_domain=str(request_payload.get("service_id", "")),
                now=now,
            ):
                return False

        return verify_login_response(
            response_payload,
            signature,
            keypair,
            hybrid_container_b64=hybrid_container_b64,
        )
    except Exception:
        return False


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
    """
    if not isinstance(service_id, str):
        raise TypeError("login(): service_id must be a str.")
    if not isinstance(callback_url, str) or not isinstance(nonce, str):
        raise TypeError("login(): callback_url and nonce must be str.")
    if keypair is None:
        raise TypeError("login(): keypair must be provided.")
    if address is None or pubkey is None:
        raise TypeError("login(): address and pubkey must be provided.")

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
# Dual-proof convenience (wallet/client side)
# ---------------------------------------------------------------------------


def build_dual_proof_login_response(
    *,
    request_payload: Dict[str, Any],
    address: str,
    pubkey: str,
    legacy_keypair: QIDKeyPair,
    binding_id: str,
    pqc_alg: str,
    ml_dsa_keypair: QIDKeyPair | None = None,
    falcon_keypair: QIDKeyPair | None = None,
    key_id: str | None = None,
    version: str = "1",
    hybrid_container_b64: Optional[str] = None,
) -> tuple[Dict[str, Any], str]:
    """
    Wallet-side helper:
    - builds login_response payload
    - enforces require='dual-proof'
    - attaches binding_id + PQC fields
    - returns (response_payload, legacy_signature)

    Notes:
    - PQC signing requires QID_PQC_BACKEND to be selected (e.g. liboqs),
      otherwise PQCBackendError will be raised (caller decides policy).
    """
    req_mode = _require_from_payload(request_payload)
    if req_mode != REQUIRE_DUAL_PROOF:
        raise ValueError("build_dual_proof_login_response requires request_payload require='dual-proof'")
    if not isinstance(binding_id, str) or not binding_id:
        raise ValueError("binding_id must be a non-empty string")

    resp = build_login_response_payload(
        request_payload,
        address=address,
        pubkey=pubkey,
        key_id=key_id,
        version=version,
    )

    # Attach binding id (domain-scoped proof anchor)
    resp["binding_id"] = binding_id

    # Attach PQC fields + signatures (non-circular; pqc_sign handles sanitation)
    sign_pqc_login_fields(
        resp,
        pqc_alg=pqc_alg,
        ml_dsa_keypair=ml_dsa_keypair,
        falcon_keypair=falcon_keypair,
    )

    # Legacy signature signs the full payload including PQC fields (fine; not circular)
    sig = sign_login_response(resp, legacy_keypair, hybrid_container_b64=hybrid_container_b64)
    return resp, sig


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
    if not isinstance(service_id, str):
        raise TypeError("register_identity(): service_id must be a str.")
    if not all(isinstance(x, str) for x in [address, pubkey, nonce, callback_url]):
        raise TypeError("register_identity(): address/pubkey/nonce/callback_url must be str.")
    if keypair is None:
        raise TypeError("register_identity(): keypair must be provided.")

    payload = build_registration_payload(
        service_id=service_id,
        address=address,
        pubkey=pubkey,
        nonce=nonce,
        callback_url=callback_url,
        version=version,
    )
    return sign_message(payload, keypair, hybrid_container_b64=hybrid_container_b64)
