from __future__ import annotations

import os

import qid.pqc_verify as pv


def _set_env(value: str | None) -> None:
    if value is None:
        os.environ.pop("QID_PQC_BACKEND", None)
    else:
        os.environ["QID_PQC_BACKEND"] = value


def test_verify_pqc_login_backend_none_fails_closed() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    try:
        _set_env(None)
        assert pv.verify_pqc_login(login_payload={}, binding_env={}) is False
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

        # ML-DSA ok (signature is in pqc_sig but payload is sanitized before verification)
        assert (
            pv.verify_pqc_login(
                login_payload={"pqc_alg": pv.ML_DSA_ALGO, "pqc_sig": "aa"},
                binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": {"ml_dsa": "aa"}}},
            )
            is True
        )

        # Falcon ok
        assert (
            pv.verify_pqc_login(
                login_payload={"pqc_alg": pv.FALCON_ALGO, "pqc_sig": "aa"},
                binding_env={"payload": {"policy": "falcon", "pqc_pubkeys": {"falcon": "aa"}}},
            )
            is True
        )

        # Hybrid strict AND ok
        assert (
            pv.verify_pqc_login(
                login_payload={
                    "pqc_alg": pv.HYBRID_ALGO,
                    "pqc_sig_ml_dsa": "aa",
                    "pqc_sig_falcon": "aa",
                },
                binding_env={
                    "payload": {
                        "policy": "hybrid",
                        "pqc_pubkeys": {"ml_dsa": "aa", "falcon": "aa"},
                    }
                },
            )
            is True
        )

    finally:
        pv.enforce_no_silent_fallback_for_alg = orig_enforce  # type: ignore[assignment]
        pv.liboqs_verify = orig_verify  # type: ignore[assignment]
        pv._b64url_decode = orig_decode  # type: ignore[assignment]
        _set_env(old)
