import os
import pytest

from qid.crypto import ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO, generate_keypair, sign_payload, verify_payload


def _has_oqs() -> bool:
    try:
        import oqs  # type: ignore
        return True
    except Exception:
        return False


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_mldsa_roundtrip() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"
    kp = generate_keypair(ML_DSA_ALGO)
    payload = {"x": 1}
    sig = sign_payload(payload, kp)
    assert verify_payload(payload, sig, kp) is True


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_falcon_roundtrip() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"
    kp = generate_keypair(FALCON_ALGO)
    payload = {"x": 2}
    sig = sign_payload(payload, kp)
    assert verify_payload(payload, sig, kp) is True


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_hybrid_and_roundtrip() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"
    kp = generate_keypair(HYBRID_ALGO)
    payload = {"x": 3}
    sig = sign_payload(payload, kp)
    assert verify_payload(payload, sig, kp) is True
