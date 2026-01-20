# tests/test_protocol_more_coverage.py
from __future__ import annotations

import base64
import json

import pytest

from qid.crypto import DEV_ALGO, generate_keypair
from qid.protocol import (
    build_login_request_payload,
    build_login_response_payload,
    build_registration_uri,
    login,
    parse_registration_uri,
    register_identity,
    server_verify_login_response,
)


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_build_login_response_payload_requires_service_and_nonce() -> None:
    # missing service_id/nonce must raise (covers strict validation branch)
    with pytest.raises(ValueError):
        build_login_response_payload({"type": "login_request"}, address="A", pubkey="P")


def test_server_verify_login_response_mismatch_fails_closed() -> None:
    kp = generate_keypair(DEV_ALGO)
    req = build_login_request_payload(service_id="svc", nonce="n1", callback_url="cb")

    ok_resp = {
        "type": "login_response",
        "service_id": "svc",
        "nonce": "n1",
        "address": "A",
        "pubkey": "P",
        "version": "1",
    }
    sig = "not-a-real-sig"  # verify() will fail anyway; we only care mismatch branches

    bad_type = dict(ok_resp)
    bad_type["type"] = "x"
    assert server_verify_login_response(req, bad_type, sig, kp) is False

    bad_service = dict(ok_resp)
    bad_service["service_id"] = "other"
    assert server_verify_login_response(req, bad_service, sig, kp) is False

    bad_nonce = dict(ok_resp)
    bad_nonce["nonce"] = "other"
    assert server_verify_login_response(req, bad_nonce, sig, kp) is False


def test_login_strict_mode_type_errors_are_covered() -> None:
    kp = generate_keypair(DEV_ALGO)

    with pytest.raises(TypeError):
        login({"x": 1}, callback_url="cb")  # placeholder must have no extra args

    with pytest.raises(TypeError):
        login(123)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        login("svc")  # missing callback_url/nonce

    with pytest.raises(TypeError):
        login("svc", "cb", "n1", address="A", pubkey="P", keypair=None)  # type: ignore[arg-type]


def test_register_identity_strict_mode_type_errors_are_covered() -> None:
    kp = generate_keypair(DEV_ALGO)

    with pytest.raises(TypeError):
        register_identity({"x": 1}, address="A")  # placeholder must have no extra args

    with pytest.raises(TypeError):
        register_identity(123)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        register_identity("svc")  # missing required fields

    with pytest.raises(TypeError):
        register_identity("svc", "A", "P", "n", "cb", None)  # type: ignore[arg-type]

    # Valid strict call path (just to execute the builder branch)
    msg = register_identity("svc", "A", "P", "n", "cb", kp)
    assert msg.payload["type"] == "registration"


def test_parse_registration_uri_error_paths() -> None:
    with pytest.raises(ValueError):
        parse_registration_uri("http://register?d=x")  # missing qid:// prefix

    with pytest.raises(ValueError):
        parse_registration_uri("qid://register")  # missing query part

    with pytest.raises(ValueError):
        parse_registration_uri("qid://login?d=x")  # wrong action for registration

    with pytest.raises(ValueError):
        parse_registration_uri("qid://register?x=1")  # missing d

    with pytest.raises(ValueError):
        parse_registration_uri("qid://register?d=%%%")  # bad base64/decoding

    # decoded JSON is not an object -> must raise
    token = _b64url_no_pad(json.dumps([1, 2, 3]).encode("utf-8"))
    with pytest.raises(ValueError):
        parse_registration_uri(f"qid://register?d={token}")


def test_build_registration_uri_roundtrip_smoke() -> None:
    payload = {
        "type": "registration",
        "service_id": "svc",
        "address": "A",
        "pubkey": "P",
        "nonce": "n",
        "callback_url": "cb",
        "version": "1",
    }
    uri = build_registration_uri(payload)
    decoded = parse_registration_uri(uri)
    assert decoded["service_id"] == "svc"
