from __future__ import annotations

import os
import pytest

import qid.pqc_verify as pv
import qid.pqc_sign as ps

from qid.crypto import DEV_ALGO, generate_keypair
from qid.pqc_backends import ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO, PQCBackendError


def _set_env(value: str | None) -> None:
    if value is None:
        os.environ.pop("QID_PQC_BACKEND", None)
    else:
        os.environ["QID_PQC_BACKEND"] = value


# ---------------------------------------------------------------------------
# pqc_verify coverage (CI-safe stubs)
# ---------------------------------------------------------------------------

def test_verify_pqc_login_backend_none_fails_closed() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    try:
        _set_env(None)
        assert pv.verify_pqc_login(login_payload={}, binding_env={}) is False
    finally:
        _set_env(old)


def test_verify_pqc_login_invalid_shapes_fail_closed() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    try:
        _set_env("liboqs")

        # binding_env missing payload
        assert pv.verify_pqc_login(login_payload={"pqc_alg": pv.ML_DSA_ALGO}, binding_env={}) is False

        # payload wrong type
        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.ML_DSA_ALGO},
            binding_env={"payload": "nope"},
        ) is False

        # pqc_pubkeys wrong type
        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.ML_DSA_ALGO},
            binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": "nope"}},
        ) is False

        # policy wrong type
        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.ML_DSA_ALGO},
            binding_env={"payload": {"policy": 123, "pqc_pubkeys": {"ml_dsa": "aa"}}},
        ) is False

        # missing pqc_alg
        assert pv.verify_pqc_login(
            login_payload={},
            binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": {"ml_dsa": "aa"}}},
        ) is False

        # invalid pqc_alg type
        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": 123},  # type: ignore[dict-item]
            binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": {"ml_dsa": "aa"}}},
        ) is False

        # unknown pqc_alg string
        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": "nope"},
            binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": {"ml_dsa": "aa"}}},
        ) is False

    finally:
        _set_env(old)


def test_verify_pqc_login_policy_mismatch_fail_closed() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    try:
        _set_env("liboqs")

        # ML-DSA requires policy in {"ml-dsa","hybrid"}
        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.ML_DSA_ALGO, "pqc_sig": "aa"},
            binding_env={"payload": {"policy": "falcon", "pqc_pubkeys": {"ml_dsa": "aa"}}},
        ) is False

        # Falcon requires policy in {"falcon","hybrid"}
        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.FALCON_ALGO, "pqc_sig": "aa"},
            binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": {"falcon": "aa"}}},
        ) is False

        # Hybrid requires policy == "hybrid"
        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.HYBRID_ALGO, "pqc_sig_ml_dsa": "aa", "pqc_sig_falcon": "aa"},
            binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": {"ml_dsa": "aa", "falcon": "aa"}}},
        ) is False

    finally:
        _set_env(old)


def test_verify_pqc_login_missing_sig_fields_fail_closed() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    try:
        _set_env("liboqs")

        # Missing pqc_sig for ML-DSA
        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.ML_DSA_ALGO},
            binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": {"ml_dsa": "aa"}}},
        ) is False

        # Missing pqc_sig for Falcon
        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.FALCON_ALGO},
            binding_env={"payload": {"policy": "falcon", "pqc_pubkeys": {"falcon": "aa"}}},
        ) is False

        # Missing hybrid sig fields
        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.HYBRID_ALGO},
            binding_env={"payload": {"policy": "hybrid", "pqc_pubkeys": {"ml_dsa": "aa", "falcon": "aa"}}},
        ) is False

    finally:
        _set_env(old)


def test_verify_pqc_login_success_paths_with_stubs() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    orig_enforce = pv.enforce_no_silent_fallback_for_alg
    orig_verify = pv.liboqs_verify
    orig_decode = pv._b64url_decode
    try:
        _set_env("liboqs")

        pv.enforce_no_silent_fallback_for_alg = lambda _alg: None  # type: ignore[assignment]
        pv.liboqs_verify = lambda _alg, _msg, _sig, _pub: True  # type: ignore[assignment]
        pv._b64url_decode = lambda _s: b"x"  # type: ignore[assignment]

        # ML-DSA ok (payload is sanitized before verification)
        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.ML_DSA_ALGO, "pqc_sig": "aa"},
            binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": {"ml_dsa": "aa"}}},
        ) is True

        # Falcon ok
        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.FALCON_ALGO, "pqc_sig": "aa"},
            binding_env={"payload": {"policy": "falcon", "pqc_pubkeys": {"falcon": "aa"}}},
        ) is True

        # Hybrid strict AND ok
        assert pv.verify_pqc_login(
            login_payload={"pqc_alg": pv.HYBRID_ALGO, "pqc_sig_ml_dsa": "aa", "pqc_sig_falcon": "aa"},
            binding_env={
                "payload": {"policy": "hybrid", "pqc_pubkeys": {"ml_dsa": "aa", "falcon": "aa"}}
            },
        ) is True

    finally:
        pv.enforce_no_silent_fallback_for_alg = orig_enforce  # type: ignore[assignment]
        pv.liboqs_verify = orig_verify  # type: ignore[assignment]
        pv._b64url_decode = orig_decode  # type: ignore[assignment]
        _set_env(old)


# ---------------------------------------------------------------------------
# pqc_sign coverage (CI-safe stubs)
# ---------------------------------------------------------------------------

def test_sign_pqc_login_fields_requires_backend_selected() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    try:
        _set_env(None)
        payload: dict = {"type": "login_response"}
        with pytest.raises(PQCBackendError):
            ps.sign_pqc_login_fields(payload, pqc_alg=ML_DSA_ALGO, ml_dsa_keypair=generate_keypair(DEV_ALGO))
    finally:
        _set_env(old)


def test_sign_pqc_login_fields_rejects_unknown_alg() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    try:
        _set_env("liboqs")
        payload: dict = {"type": "login_response"}
        with pytest.raises(ValueError):
            ps.sign_pqc_login_fields(payload, pqc_alg="nope", ml_dsa_keypair=generate_keypair(DEV_ALGO))
    finally:
        _set_env(old)


def test_sign_pqc_login_fields_ml_dsa_success_with_stubs() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    orig_enforce = ps.enforce_no_silent_fallback_for_alg
    orig_sign = ps.liboqs_sign
    orig_decode = ps._b64url_decode
    try:
        _set_env("liboqs")

        ps.enforce_no_silent_fallback_for_alg = lambda _alg: None  # type: ignore[assignment]
        ps.liboqs_sign = lambda _alg, _msg, _priv: b"sig"  # type: ignore[assignment]
        ps._b64url_decode = lambda _s: b"priv"  # type: ignore[assignment]

        kp = generate_keypair(DEV_ALGO)
        payload: dict = {"type": "login_response", "service_id": "example.com", "nonce": "n", "binding_id": "b"}

        ps.sign_pqc_login_fields(payload, pqc_alg=ML_DSA_ALGO, ml_dsa_keypair=kp)

        assert payload["pqc_alg"] == ML_DSA_ALGO
        assert "pqc_sig" in payload
        assert "pqc_sig_ml_dsa" not in payload
        assert "pqc_sig_falcon" not in payload
    finally:
        ps.enforce_no_silent_fallback_for_alg = orig_enforce  # type: ignore[assignment]
        ps.liboqs_sign = orig_sign  # type: ignore[assignment]
        ps._b64url_decode = orig_decode  # type: ignore[assignment]
        _set_env(old)


def test_sign_pqc_login_fields_falcon_success_with_stubs() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    orig_enforce = ps.enforce_no_silent_fallback_for_alg
    orig_sign = ps.liboqs_sign
    orig_decode = ps._b64url_decode
    try:
        _set_env("liboqs")

        ps.enforce_no_silent_fallback_for_alg = lambda _alg: None  # type: ignore[assignment]
        ps.liboqs_sign = lambda _alg, _msg, _priv: b"sig"  # type: ignore[assignment]
        ps._b64url_decode = lambda _s: b"priv"  # type: ignore[assignment]

        kp = generate_keypair(DEV_ALGO)
        payload: dict = {"type": "login_response", "service_id": "example.com", "nonce": "n", "binding_id": "b"}

        ps.sign_pqc_login_fields(payload, pqc_alg=FALCON_ALGO, falcon_keypair=kp)

        assert payload["pqc_alg"] == FALCON_ALGO
        assert "pqc_sig" in payload
    finally:
        ps.enforce_no_silent_fallback_for_alg = orig_enforce  # type: ignore[assignment]
        ps.liboqs_sign = orig_sign  # type: ignore[assignment]
        ps._b64url_decode = orig_decode  # type: ignore[assignment]
        _set_env(old)


def test_sign_pqc_login_fields_hybrid_success_with_stubs() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    orig_enforce = ps.enforce_no_silent_fallback_for_alg
    orig_sign = ps.liboqs_sign
    orig_decode = ps._b64url_decode
    try:
        _set_env("liboqs")

        ps.enforce_no_silent_fallback_for_alg = lambda _alg: None  # type: ignore[assignment]
        ps.liboqs_sign = lambda _alg, _msg, _priv: b"sig"  # type: ignore[assignment]
        ps._b64url_decode = lambda _s: b"priv"  # type: ignore[assignment]

        kp1 = generate_keypair(DEV_ALGO)
        kp2 = generate_keypair(DEV_ALGO)

        payload: dict = {"type": "login_response", "service_id": "example.com", "nonce": "n", "binding_id": "b"}

        ps.sign_pqc_login_fields(payload, pqc_alg=HYBRID_ALGO, ml_dsa_keypair=kp1, falcon_keypair=kp2)

        assert payload["pqc_alg"] == HYBRID_ALGO
        assert "pqc_sig_ml_dsa" in payload
        assert "pqc_sig_falcon" in payload
        assert "pqc_sig" not in payload
    finally:
        ps.enforce_no_silent_fallback_for_alg = orig_enforce  # type: ignore[assignment]
        ps.liboqs_sign = orig_sign  # type: ignore[assignment]
        ps._b64url_decode = orig_decode  # type: ignore[assignment]
        _set_env(old)


def test_sign_pqc_login_fields_missing_required_keypairs() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    orig_enforce = ps.enforce_no_silent_fallback_for_alg
    try:
        _set_env("liboqs")
        ps.enforce_no_silent_fallback_for_alg = lambda _alg: None  # type: ignore[assignment]

        payload: dict = {"type": "login_response"}

        with pytest.raises(ValueError):
            ps.sign_pqc_login_fields(payload, pqc_alg=ML_DSA_ALGO)

        with pytest.raises(ValueError):
            ps.sign_pqc_login_fields(payload, pqc_alg=FALCON_ALGO)

        with pytest.raises(ValueError):
            ps.sign_pqc_login_fields(payload, pqc_alg=HYBRID_ALGO, ml_dsa_keypair=generate_keypair(DEV_ALGO))

        with pytest.raises(ValueError):
            ps.sign_pqc_login_fields(payload, pqc_alg=HYBRID_ALGO, falcon_keypair=generate_keypair(DEV_ALGO))
    finally:
        ps.enforce_no_silent_fallback_for_alg = orig_enforce  # type: ignore[assignment]
        _set_env(old)
