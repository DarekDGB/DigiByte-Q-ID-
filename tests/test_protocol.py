"""
Tests for high-level Q-ID login helpers.
"""

from qid.protocol import (
    build_login_request_payload,
    build_login_request_uri,
    parse_login_request_uri,
)


def test_login_request_roundtrip() -> None:
    payload = build_login_request_payload(
        service_id="example.com",
        nonce="abc123",
        callback_url="https://example.com/qid",
    )

    uri = build_login_request_uri(payload)
    decoded = parse_login_request_uri(uri)

    # Basic structure check
    assert decoded["type"] == "login_request"
    assert decoded["service_id"] == "example.com"
    assert decoded["nonce"] == "abc123"
    assert decoded["callback_url"] == "https://example.com/qid"
    assert decoded["version"] == "1"
