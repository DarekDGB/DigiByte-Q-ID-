from __future__ import annotations

import importlib
import types
import pytest

import qid.pqc_backends as pb


def test_selected_backend_normalizes_and_strips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "  LiBoQs  ")
    assert pb.selected_backend() == "liboqs"


def test_selected_backend_empty_string_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "   ")
    assert pb.selected_backend() is None


def test_require_real_pqc_false_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)
    assert pb.require_real_pqc() is False


def test_require_real_pqc_true_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    assert pb.require_real_pqc() is True


def test_oqs_alg_for_rejects_non_pqc_alg() -> None:
    with pytest.raises(ValueError):
        pb._oqs_alg_for("not-a-qid-pqc-alg")


def test_validate_oqs_module_rejects_missing_signature() -> None:
    bad = types.SimpleNamespace()
    with pytest.raises(pb.PQCBackendError):
        pb._validate_oqs_module(bad)


def test_validate_oqs_module_rejects_noncallable_signature() -> None:
    bad = types.SimpleNamespace(Signature=123)
    with pytest.raises(pb.PQCBackendError):
        pb._validate_oqs_module(bad)


def test_enforce_no_silent_fallback_noop_when_backend_not_selected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)
    # Should not raise for any alg in stub mode
    pb.enforce_no_silent_fallback_for_alg(pb.ML_DSA_ALGO)
    pb.enforce_no_silent_fallback_for_alg(pb.FALCON_ALGO)
    pb.enforce_no_silent_fallback_for_alg(pb.HYBRID_ALGO)
    pb.enforce_no_silent_fallback_for_alg("not-a-qid-pqc-alg")


def test_enforce_no_silent_fallback_unknown_backend_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "unknown-backend")
    with pytest.raises(pb.PQCBackendError):
        pb.enforce_no_silent_fallback_for_alg(pb.ML_DSA_ALGO)


def test_enforce_no_silent_fallback_ignores_non_pqc_algs_even_when_backend_selected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    # Make _import_oqs explode if called to ensure we truly ignore non-PQC algs.
    monkeypatch.setattr(pb, "_import_oqs", lambda: (_ for _ in ()).throw(AssertionError("should not import oqs")))
    pb.enforce_no_silent_fallback_for_alg("not-a-qid-pqc-alg")  # must not raise


def test_liboqs_sign_unsupported_alg_raises_valueerror_before_import(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ensure we do NOT attempt to import oqs for unsupported algs.
    monkeypatch.setattr(pb, "_import_oqs", lambda: (_ for _ in ()).throw(AssertionError("should not import oqs")))
    with pytest.raises(ValueError):
        pb.liboqs_sign("not-a-qid-pqc-alg", b"m", b"k")


def test_liboqs_verify_unsupported_alg_raises_valueerror_before_import(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pb, "_import_oqs", lambda: (_ for _ in ()).throw(AssertionError("should not import oqs")))
    with pytest.raises(ValueError):
        pb.liboqs_verify("not-a-qid-pqc-alg", b"m", b"s", b"p")


def test_liboqs_sign_typeerror_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force qid.pqc.pqc_ml_dsa.sign_ml_dsa to raise TypeError so pb wraps it as PQCBackendError.
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    class FakeOQS:
        @staticmethod
        def Signature(*args, **kwargs):
            return object()

    monkeypatch.setattr(pb, "_import_oqs", lambda: FakeOQS)
    monkeypatch.setattr(pb, "_validate_oqs_module", lambda oqs: None)

    mod = importlib.import_module("qid.pqc.pqc_ml_dsa")
    monkeypatch.setattr(mod, "sign_ml_dsa", lambda **kwargs: (_ for _ in ()).throw(TypeError("bad")))

    with pytest.raises(pb.PQCBackendError):
        pb.liboqs_sign(pb.ML_DSA_ALGO, b"m", b"k")


def test_liboqs_verify_internal_exception_fail_closed_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    class FakeOQS:
        @staticmethod
        def Signature(*args, **kwargs):
            return object()

    monkeypatch.setattr(pb, "_import_oqs", lambda: FakeOQS)
    monkeypatch.setattr(pb, "_validate_oqs_module", lambda oqs: None)

    mod = importlib.import_module("qid.pqc.pqc_falcon")
    monkeypatch.setattr(mod, "verify_falcon", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))

    assert pb.liboqs_verify(pb.FALCON_ALGO, b"m", b"s", b"p") is False
