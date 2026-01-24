import os
import pytest

from qid.crypto import HYBRID_ALGO, generate_keypair, sign_payload, verify_payload
from qid.hybrid_key_container import build_container, encode_container
from qid.pqc.keygen_liboqs import generate_falcon_keypair, generate_ml_dsa_keypair


def _has_oqs() -> bool:
    try:
        import oqs  # type: ignore
        return True
    except Exception:
        return False


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_ml_dsa_roundtrip() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    pub, sec = generate_ml_dsa_keypair("ML-DSA-44")
    payload = {"x": 1}
    sig = sign_payload(payload, {"alg": "ML-DSA-44", "public_key": pub, "secret_key": sec})
    assert verify_payload(payload, sig, {"alg": "ML-DSA-44", "public_key": pub, "secret_key": sec}) is True


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_ml_dsa_tamper_fails() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    pub, sec = generate_ml_dsa_keypair("ML-DSA-44")
    payload = {"x": 10}
    sig = sign_payload(payload, {"alg": "ML-DSA-44", "public_key": pub, "secret_key": sec})

    # Tamper payload -> must fail
    assert verify_payload({"x": 11}, sig, {"alg": "ML-DSA-44", "public_key": pub, "secret_key": sec}) is False


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_falcon_roundtrip() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    pub, sec = generate_falcon_keypair("Falcon-512")
    payload = {"x": 2}
    sig = sign_payload(payload, {"alg": "Falcon-512", "public_key": pub, "secret_key": sec})
    assert verify_payload(payload, sig, {"alg": "Falcon-512", "public_key": pub, "secret_key": sec}) is True


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_falcon_wrong_pubkey_fails() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    pub1, sec1 = generate_falcon_keypair("Falcon-512")
    pub2, _sec2 = generate_falcon_keypair("Falcon-512")
    payload = {"x": 20}

    sig = sign_payload(payload, {"alg": "Falcon-512", "public_key": pub1, "secret_key": sec1})

    # Wrong public key -> must fail
    assert verify_payload(payload, sig, {"alg": "Falcon-512", "public_key": pub2, "secret_key": sec1}) is False


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_hybrid_roundtrip_with_container() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    # Generate real PQC component keys (real liboqs)
    ml_pub, ml_sec = generate_ml_dsa_keypair("ML-DSA-44")
    fa_pub, fa_sec = generate_falcon_keypair("Falcon-512")

    # Build container with BOTH public keys and BOTH secret keys (for this implementation)
    container = build_container(
        kid="test-kid",
        ml_dsa_public_key=ml_pub,
        falcon_public_key=fa_pub,
        ml_dsa_secret_key=ml_sec,
        falcon_secret_key=fa_sec,
    )
    container_b64 = encode_container(container)

    # Hybrid signing uses container, not the hybrid keypair fields
    kp_h = generate_keypair(HYBRID_ALGO)
    payload = {"x": 3}

    sig = sign_payload(payload, kp_h, hybrid_container_b64=container_b64)
    assert verify_payload(payload, sig, kp_h, hybrid_container_b64=container_b64) is True


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_hybrid_wrong_container_fails() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    ml_pub, ml_sec = generate_ml_dsa_keypair("ML-DSA-44")
    fa_pub, fa_sec = generate_falcon_keypair("Falcon-512")

    container_ok = build_container(
        kid="test-kid",
        ml_dsa_public_key=ml_pub,
        falcon_public_key=fa_pub,
        ml_dsa_secret_key=ml_sec,
        falcon_secret_key=fa_sec,
    )

    # Wrong falcon secret key in the container -> must fail
    _fa_pub2, fa_sec_bad = generate_falcon_keypair("Falcon-512")
    container_bad = build_container(
        kid="test-kid",
        ml_dsa_public_key=ml_pub,
        falcon_public_key=fa_pub,
        ml_dsa_secret_key=ml_sec,
        falcon_secret_key=fa_sec_bad,
    )

    b64_ok = encode_container(container_ok)
    b64_bad = encode_container(container_bad)

    kp_h = generate_keypair(HYBRID_ALGO)
    payload = {"x": 30}
    sig = sign_payload(payload, kp_h, hybrid_container_b64=b64_ok)

    # Wrong container -> must fail
    assert verify_payload(payload, sig, kp_h, hybrid_container_b64=b64_bad) is False
