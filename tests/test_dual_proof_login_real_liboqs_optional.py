from __future__ import annotations

import os
import pytest

from qid.binding import build_binding_payload, sign_binding
from qid.crypto import DEV_ALGO, ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO, generate_keypair
from qid.pqc_sign import sign_pqc_login_fields
from qid.protocol import (
    REQUIRE_DUAL_PROOF,
    build_login_request_payload,
    build_login_response_payload,
    server_verify_login_response,
    sign_login_response,
)


def _has_oqs() -> bool:
    try:
        import oqs  # type: ignore
        return True
    except Exception:
        return False


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_dual_proof_login_real_liboqs_ml_dsa_roundtrip() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    kp_dev = generate_keypair(DEV_ALGO)
    kp_ml = generate_keypair(ML_DSA_ALGO)

    # Binding with ML-DSA pubkey
    b_payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u=kp_ml.public_key,
        falcon_pub_b64u=None,
        created_at=100,
        expires_at=None,
    )
    b_env = sign_binding(b_payload, kp_dev)

    def resolver(bid: str):
        return b_env if bid == b_env["binding_id"] else None

    req = build_login_request_payload("example.com", "n1", "https://cb")
    req["require"] = REQUIRE_DUAL_PROOF
    req["_binding_resolver"] = resolver
    req["_now"] = 101

    resp = build_login_response_payload(req, address="ADDR", pubkey="PUB")
    resp["binding_id"] = b_env["binding_id"]

    # Client adds PQC fields + PQC signature
    sign_pqc_login_fields(resp, pqc_alg=ML_DSA_ALGO, ml_dsa_keypair=kp_ml)

    # Legacy signature still required
    sig = sign_login_response(resp, kp_dev)

    assert server_verify_login_response(req, resp, sig, kp_dev) is True


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_dual_proof_login_real_liboqs_falcon_roundtrip() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    kp_dev = generate_keypair(DEV_ALGO)
    kp_fa = generate_keypair(FALCON_ALGO)

    b_payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="falcon",
        ml_dsa_pub_b64u=None,
        falcon_pub_b64u=kp_fa.public_key,
        created_at=100,
        expires_at=None,
    )
    b_env = sign_binding(b_payload, kp_dev)

    def resolver(bid: str):
        return b_env if bid == b_env["binding_id"] else None

    req = build_login_request_payload("example.com", "nF", "https://cb")
    req["require"] = REQUIRE_DUAL_PROOF
    req["_binding_resolver"] = resolver
    req["_now"] = 101

    resp = build_login_response_payload(req, address="ADDR", pubkey="PUB")
    resp["binding_id"] = b_env["binding_id"]

    sign_pqc_login_fields(resp, pqc_alg=FALCON_ALGO, falcon_keypair=kp_fa)
    sig = sign_login_response(resp, kp_dev)

    assert server_verify_login_response(req, resp, sig, kp_dev) is True


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_dual_proof_login_real_liboqs_tamper_pqc_sig_fails() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    kp_dev = generate_keypair(DEV_ALGO)
    kp_ml = generate_keypair(ML_DSA_ALGO)

    b_payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u=kp_ml.public_key,
        falcon_pub_b64u=None,
        created_at=100,
        expires_at=None,
    )
    b_env = sign_binding(b_payload, kp_dev)

    def resolver(bid: str):
        return b_env if bid == b_env["binding_id"] else None

    req = build_login_request_payload("example.com", "nT", "https://cb")
    req["require"] = REQUIRE_DUAL_PROOF
    req["_binding_resolver"] = resolver
    req["_now"] = 101

    resp = build_login_response_payload(req, address="ADDR", pubkey="PUB")
    resp["binding_id"] = b_env["binding_id"]

    sign_pqc_login_fields(resp, pqc_alg=ML_DSA_ALGO, ml_dsa_keypair=kp_ml)

    # Tamper PQC signature -> must fail dual-proof
    if "pqc_sig" in resp and isinstance(resp["pqc_sig"], str) and resp["pqc_sig"]:
        resp["pqc_sig"] = resp["pqc_sig"][:-1] + ("A" if resp["pqc_sig"][-1] != "A" else "B")
    else:
        resp["pqc_sig"] = "AA"  # deterministic bad value

    sig = sign_login_response(resp, kp_dev)
    assert server_verify_login_response(req, resp, sig, kp_dev) is False


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_dual_proof_login_real_liboqs_hybrid_roundtrip() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    kp_dev = generate_keypair(DEV_ALGO)
    kp_ml = generate_keypair(ML_DSA_ALGO)
    kp_fa = generate_keypair(FALCON_ALGO)

    # Binding with HYBRID pubkeys
    b_payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="hybrid",
        ml_dsa_pub_b64u=kp_ml.public_key,
        falcon_pub_b64u=kp_fa.public_key,
        created_at=100,
        expires_at=None,
    )
    b_env = sign_binding(b_payload, kp_dev)

    def resolver(bid: str):
        return b_env if bid == b_env["binding_id"] else None

    req = build_login_request_payload("example.com", "n2", "https://cb")
    req["require"] = REQUIRE_DUAL_PROOF
    req["_binding_resolver"] = resolver
    req["_now"] = 101

    resp = build_login_response_payload(req, address="ADDR", pubkey="PUB")
    resp["binding_id"] = b_env["binding_id"]

    sign_pqc_login_fields(resp, pqc_alg=HYBRID_ALGO, ml_dsa_keypair=kp_ml, falcon_keypair=kp_fa)

    sig = sign_login_response(resp, kp_dev)

    assert server_verify_login_response(req, resp, sig, kp_dev) is True
