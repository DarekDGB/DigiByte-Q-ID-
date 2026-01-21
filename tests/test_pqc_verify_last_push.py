from __future__ import annotations

import os
import base64

import qid.pqc_verify as pv


def _set_env(value: str | None) -> None:
    if value is None:
        os.environ.pop("QID_PQC_BACKEND", None)
    else:
        os.environ["QID_PQC_BACKEND"] = value


def test_pqc_verify_helpers_are_exercised() -> None:
    # _payload_for_pqc removes signature fields (non-circular contract)
    src = {
        "a": 1,
        "pqc_alg": "x",
        "pqc_sig": "aa",
        "pqc_sig_ml_dsa": "bb",
        "pqc_sig_falcon": "cc",
    }
    sanitized = pv._payload_for_pqc(src)  # type: ignore[attr-defined]
    assert "pqc_sig" not in sanitized
    assert "pqc_sig_ml_dsa" not in sanitized
    assert "pqc_sig_falcon" not in sanitized
    assert sanitized["a"] == 1

    # canonical_payload_bytes is deterministic
    b1 = pv.canonical_payload_bytes({"z": 1, "a": 2})
    b2 = pv.canonical_payload_bytes({"a": 2, "z": 1})
    assert b1 == b2

    # _b64url_decode decodes urlsafe base64 without padding
    raw = b"hello"
    b64u = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    out = pv._b64url_decode(b64u)  # type: ignore[attr-defined]
    assert out == raw


def test_verify_pqc_login_hits_fail_closed_branches() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    try:
        _set_env("liboqs")

        # Policy mismatch branches
        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.ML_DSA_ALGO, "pqc_sig": "aa"},
            binding_env={"payload": {"policy": "falcon", "pqc_pubkeys": {"ml_dsa": "aa"}}},
        ) is False

        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.FALCON_ALGO, "pqc_sig": "aa"},
            binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": {"falcon": "aa"}}},
        ) is False

        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.HYBRID_ALGO, "pqc_sig_ml_dsa": "aa", "pqc_sig_falcon": "aa"},
            binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": {"ml_dsa": "aa", "falcon": "aa"}}},
        ) is False

        # Missing signature field branches (decode_sig)
        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.ML_DSA_ALGO},
            binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": {"ml_dsa": "aa"}}},
        ) is False

        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.FALCON_ALGO},
            binding_env={"payload": {"policy": "falcon", "pqc_pubkeys": {"falcon": "aa"}}},
        ) is False

        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.HYBRID_ALGO},
            binding_env={"payload": {"policy": "hybrid", "pqc_pubkeys": {"ml_dsa": "aa", "falcon": "aa"}}},
        ) is False

    finally:
        _set_env(old)
