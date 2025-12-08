"""
Simple end-to-end DigiByte Q-ID login roundtrip example.

This simulates:

1. A service generating a Q-ID login URI.
2. A wallet (Adamantine-style) preparing a signed login response.
3. The service verifying that signed response.

This uses the dev HMAC backend for signatures. In production, services
would swap this for a PQC / hybrid backend.
"""

from qid.crypto import QIDKeyPair
from qid.integration.adamantine import (
    QIDServiceConfig,
    build_qid_login_uri,
    prepare_signed_login_response,
    verify_signed_login_response_server,
)


def main() -> None:
    # 1. Service configuration (relying party)
    service = QIDServiceConfig(
        service_id="example.com",
        callback_url="https://example.com/qid/callback",
    )

    # 2. Dev keypair (HMAC-based, NOT for production)
    # In a real deployment, the wallet would hold the secret key and the
    # service would only know the public / verification part.
    keypair = QIDKeyPair(
        id="dev-hmac-primary",
        public_key="dev-hmac-primary",
        secret_key=b"dev-hmac-secret-key",
    )

    # 3. Service generates login URI with a fresh nonce
    nonce = "demo-nonce-123"  # use a secure random nonce in production
    login_uri = build_qid_login_uri(service, nonce)
    print("Q-ID login URI:")
    print(login_uri)
    print()

    # 4. Wallet side: prepare signed login response
    user_address = "dgb1qexampleaddress000000000000000000000"
    response_payload, signature = prepare_signed_login_response(
        service=service,
        login_uri=login_uri,
        address=user_address,
        keypair=keypair,
        key_id="primary",
    )

    print("Wallet response payload:")
    print(response_payload)
    print()
    print("Signature (base64url):")
    print(signature)
    print()

    # 5. Service side: verify signed response
    ok = verify_signed_login_response_server(
        service=service,
        login_uri=login_uri,
        response_payload=response_payload,
        signature=signature,
        keypair=keypair,
    )

    print("Server verification result:", ok)
    if ok:
        print("✅ Q-ID login verified – create session for", user_address)
    else:
        print("❌ Q-ID login FAILED – reject request")


if __name__ == "__main__":
    main()
