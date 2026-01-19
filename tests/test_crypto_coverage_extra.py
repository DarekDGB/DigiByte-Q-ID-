import os
import pytest

from qid.crypto import (
    DEV_ALGO,
    ML_DSA_ALGO,
    HYBRID_ALGO,
    QIDKeyPair,
    generate_dev_keypair,
    generate_keypair,
    sign_payload,
    verify_payload,
)


def test_envelope_decode_invalid_base64_fails_closed() -> None:
    kp = generate_dev_keypair()
    payload = {"a": 1}
    assert verify_payload(payload, "not-base64!!", kp) is False


def test_envelope_version_mismatch_fails_closed() -> None:
    kp = generate_dev_keypair()
    payload = {"a": 1}
    # This is base64 of {"v":999,"alg":"dev-hmac-sha256","sig":"AA=="}
    bad = "eyJ2Ijo5OTksImFsZyI6ImRldi1obWFjLXNoYTI1NiIsInNpZyI6IkFBPT0ifQ=="
    assert verify_payload(payload, bad, kp) is False


def test_backend_selected_pqc_sign_fails_closed_when_oqs_missing(monkeypatch) -> None:
    # Backend selected -> NO silent fallback allowed -> must raise PQCBackendError
    os.environ["QID_PQC_BACKEND"] = "liboqs"
    from qid import pqc_backends as pb

    monkeypatch.setattr(pb, "_import_oqs", lambda: (_ for _ in ()).throw(pb.PQCBackendError("no oqs")))

    kp = generate_keypair(ML_DSA_ALGO)
    with pytest.raises(pb.PQCBackendError):
        sign_payload({"x": 1}, kp)


def test_backend_selected_pqc_verify_fails_closed_when_oqs_missing(monkeypatch) -> None:
    # Verify must never crash: backend error => False
    os.environ["QID_PQC_BACKEND"] = "liboqs"
    from qid import pqc_backends as pb

    monkeypatch.setattr(pb, "_import_oqs", lambda: (_ for _ in ()).throw(pb.PQCBackendError("no oqs")))

    kp = generate_keypair(ML_DSA_ALGO)
    # any signature string is fine; backend is missing so verification must return False
    assert verify_payload({"x": 1}, "ZW1wdHk=", kp) is False  # base64("empty")


def test_backend_selected_hybrid_sign_raises_explicit(monkeypatch) -> None:
    # When backend selected and hybrid requested, we must fail-closed with explicit error
    os.environ["QID_PQC_BACKEND"] = "liboqs"
    from qid import pqc_backends as pb

    # Pretend oqs is present so enforce_no_silent_fallback_for_alg passes
    class FakeOQS:
        class Signature:  # pragma: no cover
            pass

    monkeypatch.setattr(pb, "_import_oqs", lambda: FakeOQS())

    kp = generate_keypair(HYBRID_ALGO)
    with pytest.raises(pb.PQCBackendError):
        sign_payload({"x": 1}, kp)
