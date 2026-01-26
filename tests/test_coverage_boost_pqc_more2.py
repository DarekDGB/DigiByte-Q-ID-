import pytest

import qid.pqc_verify as pv


def test_pqc_verify_additional_branches_for_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    # unknown backend path
    monkeypatch.setenv("QID_PQC_BACKEND", "weird")
    assert pv.verify_pqc_login(login_payload={"pqc_alg": pv.ML_DSA_ALGO}, binding_env={}) is False

    # _decode_pubkey error branches (payload not dict, pqc_pubkeys not dict, missing pubkey)
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pv, "enforce_no_silent_fallback_for_alg", lambda alg: None)
    monkeypatch.setattr(pv, "liboqs_verify", lambda *a, **k: True)

    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pv.ML_DSA_ALGO, "pqc_sig": "AA"},
        binding_env={"payload": "not-a-dict"},
    ) is False

    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pv.ML_DSA_ALGO, "pqc_sig": "AA"},
        binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": "not-a-dict"}},
    ) is False

    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pv.ML_DSA_ALGO, "pqc_sig": "AA"},
        binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": {"ml_dsa": ""}}},
    ) is False

    # hybrid signature shape missing keys
    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pv.HYBRID_ALGO, "pqc_sig": {}},
        binding_env={"payload": {"policy": "hybrid", "pqc_pubkeys": {"ml_dsa": "AA", "falcon": "AA"}}},
    ) is False
