import os
import pytest

import qid.pqc_backends as pb


def test_import_oqs_invalid_backend_object_raises(monkeypatch) -> None:
    """
    Force _import_oqs() to return a non-oqs object via monkeypatching the
    internal import mechanism so _validate_oqs_module lines are executed.
    """
    # Patch the module-global name that _import_oqs() imports.
    # If _import_oqs uses "import oqs", this won't help, so instead we patch
    # the function itself to call the validator by triggering verify path.
    class BadOQS:
        pass

    monkeypatch.setattr(pb, "_import_oqs", lambda: BadOQS())

    # liboqs_verify should validate backend and raise PQCBackendError
    with pytest.raises(pb.PQCBackendError):
        pb.liboqs_verify(pb.ML_DSA_ALGO, b"p", b"s", b"pub")


def test_enforce_backend_selected_hybrid_path(monkeypatch) -> None:
    """
    Ensure the HYBRID algorithm path in enforce_no_silent_fallback_for_alg is covered.
    """
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    class FakeOQS:
        class Signature:  # pragma: no cover
            pass

    monkeypatch.setattr(pb, "_import_oqs", lambda: FakeOQS())

    # Use the literal string to avoid relying on exported constants.
    pb.enforce_no_silent_fallback_for_alg("pqc-hybrid-ml-dsa-falcon")
