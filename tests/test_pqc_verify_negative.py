from __future__ import annotations

import pytest

import qid.pqc_verify as pv
import qid.pqc_backends as pb


def _binding_env(policy: object = "ml-dsa", ml: object = "AA", fa: object = "AA"):
    # minimal binding envelope shape expected by verify_pqc_login
    return {
        "payload": {
            "policy": policy,
            "pqc_pubkeys": {
                "ml_dsa": ml,
                "falcon": fa,
            },
        }
    }


def test_verify_pqc_login_returns_false_when_no_backend_selected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)
    ok = pv.verify_pqc_login(
        login_payload={"pqc_alg": pb.ML_DSA_ALGO, "pqc_sig": "AA"},
        binding_env=_binding_env(policy="ml-dsa", ml="AA"),
    )
    assert ok is False


def test_verify_pqc_login_false_when_binding_payload_missing() -> None:
    assert pv.verify_pqc_login(login_payload={"pqc_alg": pb.ML_DSA_ALGO}, binding_env={}) is False


def test_verify_pqc_login_false_when_binding_payload_wrong_type(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    assert pv.verify_pqc_login(login_payload={"pqc_alg": pb.ML_DSA_ALGO}, binding_env={"payload": 1}) is False


def test_verify_pqc_login_false_when_policy_missing_or_wrong_type(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pb.ML_DSA_ALGO},
        binding_env={"payload": {"policy": 1, "pqc_pubkeys": {}}},
    ) is False


def test_verify_pqc_login_false_when_pqc_pubkeys_wrong_type(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pb.ML_DSA_ALGO},
        binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": 123}},
    ) is False


def test_verify_pqc_login_false_when_alg_missing_or_wrong_type(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    assert pv.verify_pqc_login(login_payload={}, binding_env=_binding_env()) is False
    assert pv.verify_pqc_login(login_payload={"pqc_alg": 123}, binding_env=_binding_env()) is False


def test_verify_pqc_login_false_when_alg_not_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": "nope", "pqc_sig": "AA"},
        binding_env=_binding_env(),
    ) is False


def test_verify_pqc_login_enforces_no_silent_fallback_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    # Force enforce_no_silent_fallback_for_alg to raise; verify must fail-closed False.
    monkeypatch.setattr(pv, "enforce_no_silent_fallback_for_alg", lambda alg: (_ for _ in ()).throw(pb.PQCBackendError("x")))
    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pb.ML_DSA_ALGO, "pqc_sig": "AA"},
        binding_env=_binding_env(policy="ml-dsa", ml="AA"),
    ) is False


def test_verify_pqc_login_ml_dsa_policy_mismatch_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    # policy must be ml-dsa or hybrid
    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pb.ML_DSA_ALGO, "pqc_sig": "AA"},
        binding_env=_binding_env(policy="falcon", ml="AA"),
    ) is False


def test_verify_pqc_login_falcon_policy_mismatch_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    # policy must be falcon or hybrid
    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pb.FALCON_ALGO, "pqc_sig": "AA"},
        binding_env=_binding_env(policy="ml-dsa", fa="AA"),
    ) is False


def test_verify_pqc_login_hybrid_requires_policy_hybrid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    assert pv.verify_pqc_login(
        login_payload={
            "pqc_alg": pb.HYBRID_ALGO,
            "pqc_sig_ml_dsa": "AA",
            "pqc_sig_falcon": "AA",
        },
        binding_env=_binding_env(policy="ml-dsa", ml="AA", fa="AA"),
    ) is False


def test_verify_pqc_login_hybrid_missing_sig_fields_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pb.HYBRID_ALGO, "pqc_sig_ml_dsa": "AA"},
        binding_env=_binding_env(policy="hybrid", ml="AA", fa="AA"),
    ) is False


def test_verify_pqc_login_decode_errors_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    # Missing/invalid b64 strings should fail-closed False, not raise.
    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pb.ML_DSA_ALGO, "pqc_sig": ""},  # invalid
        binding_env=_binding_env(policy="ml-dsa", ml="AA"),
    ) is False


def test_verify_pqc_login_calls_liboqs_verify_and_returns_bool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    # Make b64 decode stable: "AA" decodes to b"\x00"
    monkeypatch.setattr(pv, "enforce_no_silent_fallback_for_alg", lambda alg: None)
    monkeypatch.setattr(pv, "liboqs_verify", lambda *args, **kwargs: True)

    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pb.ML_DSA_ALGO, "pqc_sig": "AA"},
        binding_env=_binding_env(policy="ml-dsa", ml="AA"),
    ) is True


def test_verify_pqc_login_payload_for_pqc_removes_sig_fields() -> None:
    lp = {"a": 1, "pqc_sig": "X", "pqc_sig_ml_dsa": "Y", "pqc_sig_falcon": "Z"}
    d = pv._payload_for_pqc(lp)
    assert "pqc_sig" not in d
    assert "pqc_sig_ml_dsa" not in d
    assert "pqc_sig_falcon" not in d
    assert d["a"] == 1
