import os
import pytest

import qid.pqc_backends as pb


def test_enforce_unknown_backend_raises() -> None:
    os.environ["QID_PQC_BACKEND"] = "unknown-backend"
    with pytest.raises(pb.PQCBackendError):
        pb.enforce_no_silent_fallback_for_alg(pb.ML_DSA_ALGO)


def test_liboqs_sign_typeerror_path_raises_pqcbackenderror(monkeypatch) -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    class FakeSig:
        def __init__(self, *args, **kwargs):
            # Trigger the TypeError branch inside liboqs_sign
            raise TypeError("no secret-key ctor")

    class FakeOQS:
        Signature = FakeSig

    monkeypatch.setattr(pb, "_import_oqs", lambda: FakeOQS())

    with pytest.raises(pb.PQCBackendError):
        pb.liboqs_sign(pb.ML_DSA_ALGO, b"payload", b"priv")


def test_liboqs_verify_returns_false_on_internal_error(monkeypatch) -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    class FakeVerifier:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def verify(self, payload, sig, pub):
            raise RuntimeError("boom")

    class FakeOQS:
        class Signature:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return FakeVerifier()

            def __exit__(self, exc_type, exc, tb):
                return False

    monkeypatch.setattr(pb, "_import_oqs", lambda: FakeOQS())

    assert pb.liboqs_verify(pb.FALCON_ALGO, b"p", b"s", b"pub") is False
