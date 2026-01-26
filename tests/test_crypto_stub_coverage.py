import pytest

from qid.crypto import (
    DEV_ALGO,
    ML_DSA_ALGO,
    FALCON_ALGO,
    HYBRID_ALGO,
    QIDKeyPair,
    generate_keypair,
    sign_payload,
    verify_payload,
)


def test_stub_sign_and_verify_dev_algo_roundtrip() -> None:
    kp = generate_keypair(DEV_ALGO)
    payload = {"a": 1}

    sig = sign_payload(payload, kp)
    assert verify_payload(payload, sig, kp) is True


def test_stub_sign_and_verify_pqc_algorithms_roundtrip() -> None:
    payload = {"x": 42}

    for alg in (ML_DSA_ALGO, FALCON_ALGO):
        kp = generate_keypair(alg)
        sig = sign_payload(payload, kp)
        assert verify_payload(payload, sig, kp) is True


def test_stub_hybrid_sign_and_verify_roundtrip() -> None:
    payload = {"hybrid": True}

    kp = generate_keypair(HYBRID_ALGO)
    sig = sign_payload(payload, kp)

    assert verify_payload(payload, sig, kp) is True


def test_stub_verify_fails_on_tampered_payload() -> None:
    kp = generate_keypair(DEV_ALGO)
    sig = sign_payload({"a": 1}, kp)

    # Different payload must fail
    assert verify_payload({"a": 2}, sig, kp) is False


def test_stub_verify_fails_on_wrong_key() -> None:
    payload = {"secure": True}

    kp1 = generate_keypair(DEV_ALGO)
    kp2 = generate_keypair(DEV_ALGO)

    sig = sign_payload(payload, kp1)

    assert verify_payload(payload, sig, kp2) is False


def test_invalid_algorithm_in_keypair_fails_cleanly() -> None:
    bad_kp = QIDKeyPair(
        algorithm="not-a-real-algo",
        secret_key="AA==",
        public_key="AA==",
    )

    with pytest.raises(ValueError):
        sign_payload({"x": 1}, bad_kp)
