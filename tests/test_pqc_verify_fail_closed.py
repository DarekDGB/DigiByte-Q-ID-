from __future__ import annotations

import os

from qid.pqc_verify import verify_pqc_login


def test_verify_pqc_login_no_backend_selected_fails_closed() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    try:
        os.environ.pop("QID_PQC_BACKEND", None)
        ok = verify_pqc_login(login_payload={}, binding_env={})
        assert ok is False
    finally:
        if old is None:
            os.environ.pop("QID_PQC_BACKEND", None)
        else:
            os.environ["QID_PQC_BACKEND"] = old


def test_verify_pqc_login_unknown_backend_fails_closed() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    try:
        os.environ["QID_PQC_BACKEND"] = "unknown"
        ok = verify_pqc_login(
            login_payload={"pqc_alg": "pqc-ml-dsa"},
            binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": {"ml_dsa": "aa"}}},
        )
        assert ok is False
    finally:
        if old is None:
            os.environ.pop("QID_PQC_BACKEND", None)
        else:
            os.environ["QID_PQC_BACKEND"] = old


def test_verify_pqc_login_liboqs_missing_dep_fails_closed() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    try:
        os.environ["QID_PQC_BACKEND"] = "liboqs"
        ok = verify_pqc_login(
            login_payload={"pqc_alg": "pqc-ml-dsa", "pqc_sig": "aa"},
            binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": {"ml_dsa": "aa"}}},
        )
        # In CI, oqs is not installed => must fail-closed (False), not crash.
        assert ok is False
    finally:
        if old is None:
            os.environ.pop("QID_PQC_BACKEND", None)
        else:
            os.environ["QID_PQC_BACKEND"] = old
