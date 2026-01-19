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

import os
import pytest

from qid.crypto import ML_DSA_ALGO, generate_keypair, sign_payload
from qid.pqc_backends import PQCBackendError


def test_crypto_blocks_pqc_when_backend_selected() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"
    kp = generate_keypair(ML_DSA_ALGO)
    with pytest.raises(PQCBackendError):
        sign_payload({"x": 1}, kp)
    os.environ.pop("QID_PQC_BACKEND", None)
