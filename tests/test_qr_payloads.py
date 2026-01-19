import pytest

from qid.qr_payloads import encode_login_request, decode_login_request


def test_qr_login_roundtrip() -> None:
    payload = {
        "type": "login_request",
        "service_id": "example.com",
        "nonce": "abc123",
        "callback_url": "https://example.com/qid",
        "version": "1",
    }
    uri = encode_login_request(payload)
    decoded = decode_login_request(uri)
    assert decoded == payload


def test_qr_decode_rejects_missing_prefix() -> None:
    with pytest.raises(ValueError):
        decode_login_request("http://login?d=abc")


def test_qr_decode_rejects_missing_query() -> None:
    with pytest.raises(ValueError):
        decode_login_request("qid://login")


def test_qr_decode_rejects_wrong_action() -> None:
    with pytest.raises(ValueError):
        decode_login_request("qid://register?d=abc")


def test_qr_decode_rejects_missing_d_param() -> None:
    with pytest.raises(ValueError):
        decode_login_request("qid://login?x=1")


def test_qr_decode_rejects_bad_base64() -> None:
    with pytest.raises(ValueError):
        decode_login_request("qid://login?d=%%%notbase64%%%")


def test_qr_decode_rejects_non_object_json() -> None:
    # base64url(JSON("hello")) => a valid decode, but payload must be object
    uri = "qid://login?d=ImhlbGxvIg"  # "hello"
    with pytest.raises(ValueError):
        decode_login_request(uri)
