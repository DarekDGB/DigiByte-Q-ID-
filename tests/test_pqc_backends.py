import os
import pytest

import qid.pqc_backends as pb


def test_selected_backend_none_when_unset() -> None:
    os.environ.pop("QID_PQC_BACKEND", None)
    assert pb.selected_backend() is None
    assert pb.require_real_pqc() is False


def test_selected_backend_normalizes_and_trims() -> None:
    os.environ["QID_PQC_BACKEND"] = "  LiBoQs  "
    assert pb.selected_backend() == "liboqs"
    assert pb.require_real_pqc() is True
    os.environ.pop("QID_PQC_BACKEND", None)


def test_enforce_no_silent_fallback_allows_when_unset() -> None:
    os.environ.pop("QID_PQC_BACKEND", None)
    # Should not raise for any alg when backend is not selected
    pb.enforce_no_silent_fallback_for_alg("pqc-ml-dsa")
    pb.enforce_no_silent_fallback_for_alg("pqc-falcon")
    pb.enforce_no_silent_fallback_for_alg("pqc-hybrid-ml-dsa-falcon")
    pb.enforce_no_silent_fallback_for_alg("dev-hmac-sha256")


def test_enforce_no_silent_fallback_rejects_unknown_backend() -> None:
    os.environ["QID_PQC_BACKEND"] = "something-else"
    with pytest.raises(pb.PQCBackendError):
        pb.enforce_no_silent_fallback_for_alg("pqc-ml-dsa")
    os.environ.pop("QID_PQC_BACKEND", None)


def test_enforce_no_silent_fallback_blocks_pqc_algs_when_selected() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"
    with pytest.raises(pb.PQCBackendError):
        pb.enforce_no_silent_fallback_for_alg("pqc-ml-dsa")
    with pytest.raises(pb.PQCBackendError):
        pb.enforce_no_silent_fallback_for_alg("pqc-falcon")
    with pytest.raises(pb.PQCBackendError):
        pb.enforce_no_silent_fallback_for_alg("pqc-hybrid-ml-dsa-falcon")

    # dev is allowed even when PQC backend selected
    pb.enforce_no_silent_fallback_for_alg("dev-hmac-sha256")
    os.environ.pop("QID_PQC_BACKEND", None)


def test_liboqs_sign_verify_unsupported_alg_raises_valueerror() -> None:
    with pytest.raises(ValueError):
        pb.liboqs_sign("dev-hmac-sha256", b"x", b"k")
    with pytest.raises(ValueError):
        pb.liboqs_verify("dev-hmac-sha256", b"x", b"s", b"p")


def test_liboqs_sign_verify_fail_closed_when_oqs_missing(monkeypatch) -> None:
    # Force import to fail deterministically
    def boom():
        raise pb.PQCBackendError("no oqs")

    monkeypatch.setattr(pb, "_import_oqs", boom)

    with pytest.raises(pb.PQCBackendError):
        pb.liboqs_sign("pqc-ml-dsa", b"payload", b"priv")
    with pytest.raises(pb.PQCBackendError):
        pb.liboqs_verify("pqc-falcon", b"payload", b"sig", b"pub")
