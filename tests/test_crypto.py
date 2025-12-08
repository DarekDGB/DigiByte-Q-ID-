from qid.crypto import (
    DEV_ALGO,
    ML_DSA_ALGO,
    FALCON_ALGO,
    HYBRID_ALGO,
    generate_dev_keypair,
    generate_keypair,
    sign_payload,
    verify_payload,
)


def _roundtrip_for_algorithm(algorithm: str) -> None:
    keypair = generate_keypair(algorithm)
    payload = {
        "type": "login_response",
        "service_id": "example.com",
        "nonce": "abc123",
        "success": True,
    }

    signature = sign_payload(payload, keypair)
    assert isinstance(signature, str)
    assert verify_payload(payload, signature, keypair)

    # Tamper with payload: verification must fail.
    tampered = dict(payload)
    tampered["nonce"] = "different"
    assert not verify_payload(tampered, signature, keypair)


def test_dev_backend_roundtrip():
    # Keep explicit test for the default dev backend.
    keypair = generate_dev_keypair()
    payload = {"message": "hello", "nonce": "123"}
    signature = sign_payload(payload, keypair)

    assert verify_payload(payload, signature, keypair)
    tampered = {"message": "hello", "nonce": "999"}
    assert not verify_payload(tampered, signature, keypair)


def test_pqc_mldsa_backend_roundtrip():
    _roundtrip_for_algorithm(ML_DSA_ALGO)


def test_pqc_falcon_backend_roundtrip():
    _roundtrip_for_algorithm(FALCON_ALGO)


def test_hybrid_backend_roundtrip():
    _roundtrip_for_algorithm(HYBRID_ALGO)
