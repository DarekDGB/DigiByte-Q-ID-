from qid.protocol import (
    build_registration_payload,
    build_registration_uri,
    parse_registration_uri,
)


def test_registration_roundtrip():
    payload = build_registration_payload(
        service_id="example.com",
        address="dgb1qxyz123example",
        pubkey="quantum-safe-public-key",
        nonce="abc123",
        callback_url="https://example.com/callback",
    )

    uri = build_registration_uri(payload)
    decoded = parse_registration_uri(uri)

    assert decoded["type"] == "registration"
    assert decoded["service_id"] == "example.com"
    assert decoded["address"] == "dgb1qxyz123example"
    assert decoded["pubkey"] == "quantum-safe-public-key"
    assert decoded["nonce"] == "abc123"
    assert decoded["callback_url"] == "https://example.com/callback"
    assert decoded["version"] == "1"
