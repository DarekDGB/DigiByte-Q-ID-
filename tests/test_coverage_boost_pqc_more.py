from __future__ import annotations

import os
import types
import pytest

import qid.pqc_backends as pb
import qid.pqc_verify as pv


class _FakeOQSModule:
    """Minimal object that looks like python-oqs for our branch coverage."""

    class Signature:
        def __init__(self, *args, **kwargs):
            pass


def _binding_env(policy: str, ml: str | None = None, fa: str | None = None) -> dict:
    pubkeys: dict[str, str] = {}
    if ml is not None:
        pubkeys["ml_dsa"] = ml
    if fa is not None:
        pubkeys["falcon"] = fa
    return {"payload": {"policy": policy, "pqc_pubkeys": pubkeys}}


def test_pqc_backends_selected_backend_normalization_and_require_real() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    try:
        os.environ.pop("QID_PQC_BACKEND", None)
        assert pb.selected_backend() is None
        assert pb.require_real_pqc() is False

        os.environ["QID_PQC_BACKEND"] = "   LiBoQs  "
        assert pb.selected_backend() == "liboqs"
        assert pb.require_real_pqc() is True
    finally:
        if old is None:
            os.environ.pop("QID_PQC_BACKEND", None)
        else:
            os.environ["QID_PQC_BACKEND"] = old


def test_pqc_backends_unknown_backend_raises() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    try:
        os.environ["QID_PQC_BACKEND"] = "weird"
        with pytest.raises(pb.PQCBackendError):
            pb.enforce_no_silent_fallback_for_alg(pb.ML_DSA_ALGO)
    finally:
        if old is None:
            os.environ.pop("QID_PQC_BACKEND", None)
        else:
            os.environ["QID_PQC_BACKEND"] = old


def test_pqc_backends_import_disabled_by_tests_raises() -> None:
    old_env = os.environ.get("QID_PQC_BACKEND")
    old_oqs = pb.oqs
    try:
        os.environ["QID_PQC_BACKEND"] = "liboqs"
        pb.oqs = None  # explicit disabled state
        with pytest.raises(pb.PQCBackendError):
            pb.enforce_no_silent_fallback_for_alg(pb.ML_DSA_ALGO)
    finally:
        pb.oqs = old_oqs
        if old_env is None:
            os.environ.pop("QID_PQC_BACKEND", None)
        else:
            os.environ["QID_PQC_BACKEND"] = old_env


def test_pqc_backends_cached_module_path_is_used() -> None:
    old_env = os.environ.get("QID_PQC_BACKEND")
    old_oqs = pb.oqs
    try:
        os.environ["QID_PQC_BACKEND"] = "liboqs"
        pb.oqs = _FakeOQSModule()  # cached “module”
        # Should validate and not import
        pb.enforce_no_silent_fallback_for_alg(pb.ML_DSA_ALGO)
        pb.enforce_no_silent_fallback_for_alg(pb.FALCON_ALGO)
    finally:
        pb.oqs = old_oqs
        if old_env is None:
            os.environ.pop("QID_PQC_BACKEND", None)
        else:
            os.environ["QID_PQC_BACKEND"] = old_env


def test_pqc_backends_liboqs_sign_falcon_calls_signer(monkeypatch: pytest.MonkeyPatch) -> None:
    # Hit FALCON sign branch without real oqs installed.
    fake_mod = _FakeOQSModule()
    monkeypatch.setattr(pb, "_import_oqs", lambda: fake_mod)
    monkeypatch.setattr(pb, "_validate_oqs_module", lambda _m: None)

    # Patch signer function in its real module path.
    import qid.pqc.pqc_falcon as pf

    monkeypatch.setattr(pf, "sign_falcon", lambda **kwargs: b"ok-falcon")

    out = pb.liboqs_sign(pb.FALCON_ALGO, b"m", b"k")
    assert out == b"ok-falcon"


def test_pqc_verify_payload_for_pqc_removes_sig_fields() -> None:
    src = {
        "a": 1,
        "pqc_alg": "x",
        "pqc_sig": "aa",
        "pqc_sig_ml_dsa": "bb",
        "pqc_sig_falcon": "cc",
    }
    sanitized = pv._payload_for_pqc(src)  # type: ignore[attr-defined]
    assert sanitized["a"] == 1
    assert "pqc_alg" not in sanitized
    assert "pqc_sig" not in sanitized
    assert "pqc_sig_ml_dsa" not in sanitized
    assert "pqc_sig_falcon" not in sanitized


def test_pqc_verify_backend_none_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)
    assert pv.verify_pqc_login(login_payload={}, binding_env={}) is False


def test_pqc_verify_unknown_backend_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "unknown")
    assert (
        pv.verify_pqc_login(
            login_payload={"pqc_alg": pb.ML_DSA_ALGO, "pqc_sig": "AA"},
            binding_env=_binding_env("ml-dsa", ml="AA"),
        )
        is False
    )


def test_pqc_verify_shapes_and_policy_mismatch_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    # missing binding_env payload
    assert pv.verify_pqc_login(login_payload={"pqc_alg": pb.ML_DSA_ALGO}, binding_env={}) is False

    # policy mismatch for ML-DSA
    assert (
        pv.verify_pqc_login(
            login_payload={"pqc_alg": pb.ML_DSA_ALGO, "pqc_sig": "AA"},
            binding_env=_binding_env("falcon", ml="AA"),
        )
        is False
    )


def test_pqc_verify_success_paths_with_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    # Avoid real backend requirements and avoid real base64 decoding.
    monkeypatch.setattr(pv, "enforce_no_silent_fallback_for_alg", lambda _alg: None)
    monkeypatch.setattr(pv, "_b64url_decode", lambda _s: b"x")
    monkeypatch.setattr(pv, "liboqs_verify", lambda *a, **k: True)

    # ML-DSA
    assert (
        pv.verify_pqc_login(
            login_payload={"pqc_alg": pb.ML_DSA_ALGO, "pqc_sig": "AA"},
            binding_env=_binding_env("ml-dsa", ml="AA"),
        )
        is True
    )

    # Falcon
    assert (
        pv.verify_pqc_login(
            login_payload={"pqc_alg": pb.FALCON_ALGO, "pqc_sig": "AA"},
            binding_env=_binding_env("falcon", fa="AA"),
        )
        is True
    )

    # Hybrid strict-AND
    assert (
        pv.verify_pqc_login(
            login_payload={
                "pqc_alg": pb.HYBRID_ALGO,
                "pqc_sig_ml_dsa": "AA",
                "pqc_sig_falcon": "AA",
            },
            binding_env=_binding_env("hybrid", ml="AA", fa="AA"),
        )
        is True
    )


def test_pqc_verify_fail_closed_on_internal_verify_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pv, "enforce_no_silent_fallback_for_alg", lambda _alg: None)
    monkeypatch.setattr(pv, "_b64url_decode", lambda _s: b"x")

    def boom(*args, **kwargs):
        raise RuntimeError("x")

    monkeypatch.setattr(pv, "liboqs_verify", boom)

    assert (
        pv.verify_pqc_login(
            login_payload={"pqc_alg": pb.ML_DSA_ALGO, "pqc_sig": "AA"},
            binding_env=_binding_env("ml-dsa", ml="AA"),
        )
        is False
    )
