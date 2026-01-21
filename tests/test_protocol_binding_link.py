from __future__ import annotations

from qid.binding import build_binding_payload, sign_binding
from qid.crypto import generate_keypair
from qid.protocol import (
    REQUIRE_DUAL_PROOF,
    build_login_request_payload,
    build_login_response_payload,
    server_verify_login_response,
    sign_login_response,
)


def test_dual_proof_login_requires_valid_binding_and_resolver() -> None:
    kp = generate_keypair()

    # Request demands dual-proof
    req = build_login_request_payload("example.com", "n1", "https://cb")
    req["require"] = REQUIRE_DUAL_PROOF

    # Create a valid binding for this domain
    b_payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="ml",
        falcon_pub_b64u=None,
        created_at=100,
        expires_at=None,
    )
    b_env = sign_binding(b_payload, kp)

    def resolver(bid: str):
        return b_env if bid == b_env["binding_id"] else None

    # Response must include binding_id
    resp = build_login_response_payload(
        req,
        address="ADDR",
        pubkey="PUB",
        binding_id=b_env["binding_id"],
    )
    sig = sign_login_response(resp, kp)

    assert (
        server_verify_login_response(
            req,
            resp,
            sig,
            kp,
            binding_resolver=resolver,
            now=101,
        )
        is True
    )


def test_dual_proof_login_missing_binding_id_rejected_at_build_time() -> None:
    kp = generate_keypair()
    req = build_login_request_payload("example.com", "n2", "https://cb")
    req["require"] = REQUIRE_DUAL_PROOF

    try:
        _ = build_login_response_payload(req, address="ADDR", pubkey="PUB")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_dual_proof_login_missing_resolver_fails_closed() -> None:
    kp = generate_keypair()
    req = build_login_request_payload("example.com", "n3", "https://cb")
    req["require"] = REQUIRE_DUAL_PROOF

    b_payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="falcon",
        ml_dsa_pub_b64u=None,
        falcon_pub_b64u="fa",
        created_at=100,
        expires_at=None,
    )
    b_env = sign_binding(b_payload, kp)

    resp = build_login_response_payload(
        req,
        address="ADDR",
        pubkey="PUB",
        binding_id=b_env["binding_id"],
    )
    sig = sign_login_response(resp, kp)

    # No resolver passed => fail-closed
    assert server_verify_login_response(req, resp, sig, kp, now=101) is False


def test_dual_proof_login_domain_mismatch_binding_fails() -> None:
    kp = generate_keypair()
    req = build_login_request_payload("example.com", "n4", "https://cb")
    req["require"] = REQUIRE_DUAL_PROOF

    # Binding for a different domain
    b_payload = build_binding_payload(
        domain="evil.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="ml",
        falcon_pub_b64u=None,
        created_at=100,
        expires_at=None,
    )
    b_env = sign_binding(b_payload, kp)

    def resolver(bid: str):
        return b_env if bid == b_env["binding_id"] else None

    resp = build_login_response_payload(
        req,
        address="ADDR",
        pubkey="PUB",
        binding_id=b_env["binding_id"],
    )
    sig = sign_login_response(resp, kp)

    assert (
        server_verify_login_response(
            req,
            resp,
            sig,
            kp,
            binding_resolver=resolver,
            now=101,
        )
        is False
    )
