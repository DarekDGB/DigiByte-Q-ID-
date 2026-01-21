from __future__ import annotations

from qid.binding import build_binding_payload, sign_binding
from qid.crypto import generate_keypair
from qid.protocol import (
    REQUIRE_DUAL_PROOF,
    REQUIRE_LEGACY,
    build_login_request_payload,
    build_login_response_payload,
    server_verify_login_response,
    sign_login_response,
)


def test_require_defaults_to_legacy_and_is_signed() -> None:
    kp = generate_keypair()
    req = build_login_request_payload("example.com", "n1", "https://cb")
    assert req["require"] == REQUIRE_LEGACY

    resp = build_login_response_payload(req, address="A", pubkey="P")
    assert resp["require"] == REQUIRE_LEGACY

    sig = sign_login_response(resp, kp)
    assert server_verify_login_response(req, resp, sig, kp) is True

    # Any change to require breaks verification (signed input).
    resp2 = dict(resp)
    resp2["require"] = REQUIRE_DUAL_PROOF
    assert server_verify_login_response(req, resp2, sig, kp) is False


def test_require_dual_proof_must_match_request_and_response() -> None:
    kp = generate_keypair()
    req = build_login_request_payload("example.com", "n2", "https://cb")
    req["require"] = REQUIRE_DUAL_PROOF

    # Create binding + provide resolver via reserved request payload hook
    b_payload = build_binding_payload(
        domain="example.com",
        address="A",
        policy="ml-dsa",
        ml_dsa_pub_b64u="ml",
        falcon_pub_b64u=None,
        created_at=100,
        expires_at=None,
    )
    b_env = sign_binding(b_payload, kp)

    def resolver(bid: str):
        return b_env if bid == b_env["binding_id"] else None

    req["_binding_resolver"] = resolver
    req["_now"] = 101

    resp = build_login_response_payload(req, address="A", pubkey="P")
    resp["binding_id"] = b_env["binding_id"]
    assert resp["require"] == REQUIRE_DUAL_PROOF

    sig = sign_login_response(resp, kp)
    assert server_verify_login_response(req, resp, sig, kp) is True


def test_invalid_require_rejects_fail_closed() -> None:
    kp = generate_keypair()
    req = build_login_request_payload("example.com", "n3", "https://cb")
    req["require"] = "maybe"  # invalid

    resp = {
        "type": "login_response",
        "service_id": "example.com",
        "nonce": "n3",
        "address": "A",
        "pubkey": "P",
        "require": "maybe",
        "version": "1",
    }
    sig = sign_login_response(resp, kp)
    assert server_verify_login_response(req, resp, sig, kp) is False
