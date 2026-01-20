"""
MIT License
Copyright (c) 2025 DarekDGB
"""

from __future__ import annotations

import pytest

from qid.crypto import (
    DEV_ALGO,
    ML_DSA_ALGO,
    FALCON_ALGO,
    HYBRID_ALGO,
    generate_keypair,
    sign_payload,
    verify_payload,
)
from qid.hybrid_key_container import (
    build_container,
    try_decode_container,
)
from qid.qr_payloads import (
    build_qr_payload,
    parse_qr_payload,
)


def test_crypto_rejects_unknown_algorithm() -> None:
    with pytest.raises(ValueError):
        generate_keypair("unknown-algo")  # type: ignore[arg-type]


def test_crypto_verify_fails_on_malformed_envelope() -> None:
    kp = generate_keypair(DEV_ALGO)
    payload = {"x": 1}

    # invalid base64 envelope
    assert verify_payload(payload, "%%%bad%%%", kp) is False


def test_crypto_alg_mismatch_fails_closed() -> None:
    payload = {"x": 1}
    kp1 = generate_keypair(DEV_ALGO)
    kp2 = generate_keypair(ML_DSA_ALGO)

    sig = sign_payload(payload, kp1)
    assert verify_payload(payload, sig, kp2) is False


def test_hybrid_container_build_and_decode_roundtrip() -> None:
    kp = generate_keypair(HYBRID_ALGO)

    container = build_container(
        alg=HYBRID_ALGO,
        ml_dsa_pub=kp.public_key,
        falcon_pub=kp.public_key,
    )

    decoded = try_decode_container(container)
    assert decoded.alg == HYBRID_ALGO
    assert decoded.ml_dsa.public_key
    assert decoded.falcon.public_key


def test_hybrid_container_decode_rejects_garbage() -> None:
    assert try_decode_container("%%%bad%%%") is None


def test_qr_payload_roundtrip() -> None:
    payload = {"type": "login", "n": "1"}
    qr = build_qr_payload(payload)
    parsed = parse_qr_payload(qr)
    assert parsed == payload


def test_qr_payload_rejects_invalid_input() -> None:
    with pytest.raises(ValueError):
        parse_qr_payload("not-a-qr-payload")
