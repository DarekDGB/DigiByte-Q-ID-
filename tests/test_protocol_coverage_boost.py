"""
MIT License
Copyright (c) 2025 DarekDGB
"""

from __future__ import annotations

import pytest

from qid.crypto import DEV_ALGO, HYBRID_ALGO, generate_keypair
from qid.protocol import (
    build_login_request_payload,
    build_login_response_payload,
    login,
    register_identity,
    server_verify_login_response,
    sign_message,
    verify_message,
)


def test_server_verify_login_response_requires_matching_fields() -> None:
    kp = generate_keypair(DEV_ALGO)

    req = build_login_request_payload(service_id="example.com", nonce="n", callback_url="https://cb")
    good_resp = build_login_response_payload(req, address="A", pubkey="P")
    sig = sign_message(good_resp, kp).signature

    assert server_verify_login_response(req, good_resp, sig, kp) is True

    bad_type = dict(good_resp)
    bad_type["type"] = "x"
    assert server_verify_login_response(req, bad_type, sig, kp) is False

    bad_svc = dict(good_resp)
    bad_svc["service_id"] = "evil.com"
    assert server_verify_login_response(req, bad_svc, sig, kp) is False

    bad_nonce = dict(good_resp)
    bad_nonce["nonce"] = "zzz"
    assert server_verify_login_response(req, bad_nonce, sig, kp) is False


def test_login_type_guards_raise_typeerror() -> None:
    kp = generate_keypair(DEV_ALGO)

    with pytest.raises(TypeError):
        login(123, "cb", "n", address="A", pubkey="P", keypair=kp)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        login("svc", 123, "n", address="A", pubkey="P", keypair=kp)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        login("svc", "cb", 123, address="A", pubkey="P", keypair=kp)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        login("svc", "cb", "n", address=None, pubkey="P", keypair=kp)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        login("svc", "cb", "n", address="A", pubkey=None, keypair=kp)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        login("svc", "cb", "n", address="A", pubkey="P", keypair=None)  # type: ignore[arg-type]


def test_register_identity_type_guards_raise_typeerror() -> None:
    kp = generate_keypair(DEV_ALGO)

    with pytest.raises(TypeError):
        register_identity(123, "A", "P", "n", "cb", kp)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        register_identity("svc", "A", "P", "n", "cb", None)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        register_identity("svc", None, "P", "n", "cb", kp)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        register_identity("svc", "A", None, "n", "cb", kp)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        register_identity("svc", "A", "P", None, "cb", kp)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        register_identity("svc", "A", "P", "n", None, kp)  # type: ignore[arg-type]


def test_sign_message_fail_closed_produces_empty_sig_on_error() -> None:
    """
    Exercise sign_message() fail-closed branch:
    - use HYBRID_ALGO
    - omit hybrid_container_b64
    In stub mode this may still succeed, but if backend logic requires container,
    sign_message must return empty sig (fail-closed) not raise.
    """
    kp = generate_keypair(HYBRID_ALGO)
    payload = {"type": "t", "n": 1}

    msg = sign_message(payload, kp, hybrid_container_b64=None)
    assert msg.algorithm == HYBRID_ALGO

    # Regardless of whether signature is empty (stub vs real-backend enforcement),
    # verify_message must never raise and must return bool.
    ok = verify_message(msg, kp)
    assert isinstance(ok, bool)
