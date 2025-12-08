from qid.crypto import generate_dev_keypair
from qid.protocol import (
    build_login_request_payload,
    build_login_response_payload,
    sign_login_response,
    verify_login_response,
    server_verify_login_response,
)


def test_signed_login_response_roundtrip() -> None:
    keypair = generate_dev_keypair()

    # Simulate a service creating a login request
    login_request = build_login_request_payload(
        service_id="example.com",
        nonce="abc123",
        callback_url="https://example.com/qid",
    )

    # Wallet builds and signs a response
    response_payload = build_login_response_payload(
        login_request,
        address="dgb1qxyz123example",
        pubkey=keypair.public_key,
        key_id="primary",
    )

    signature = sign_login_response(response_payload, keypair)

    # Basic signature verification
    assert verify_login_response(response_payload, signature, keypair)

    # Reference server-side verification flow
    assert server_verify_login_response(
        login_request,
        response_payload,
        signature,
        keypair,
    )


def test_signed_login_response_rejects_tampering() -> None:
    keypair = generate_dev_keypair()

    login_request = build_login_request_payload(
        service_id="example.com",
        nonce="abc123",
        callback_url="https://example.com/qid",
    )

    response_payload = build_login_response_payload(
        login_request,
        address="dgb1qxyz123example",
        pubkey=keypair.public_key,
    )

    signature = sign_login_response(response_payload, keypair)

    # Tamper with the response → server verification must fail
    tampered = dict(response_payload)
    tampered["address"] = "dgb1qtamperedaddress"

    assert not verify_login_response(tampered, signature, keypair)
    assert not server_verify_login_response(
        login_request,
        tampered,
        signature,
        keypair,
    )
