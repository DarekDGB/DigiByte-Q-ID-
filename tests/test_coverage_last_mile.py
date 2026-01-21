from __future__ import annotations

import os

from qid.binding import build_binding_payload, verify_binding
from qid.crypto import generate_keypair
from qid import pqc_backends
from qid.qr_payloads import build_qr_payload, parse_qr_payload


def test_verify_binding_rejects_non_mapping_and_bad_shapes() -> None:
    kp = generate_keypair()

    assert verify_binding("not-a-mapping", kp, expected_domain="example.com") is False  # type: ignore[arg-type]
    assert verify_binding({}, kp, expected_domain="example.com") is False

    env = {"payload": {}, "sig": "x", "binding_id": "y"}
    assert verify_binding(env, kp, expected_domain="example.com") is False


def test_verify_binding_expiry_branch_with_now_default() -> None:
    kp = generate_keypair()
    payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="falcon",
        ml_dsa_pub_b64u=None,
        falcon_pub_b64u="fa",
        created_at=100,
        expires_at=1,
    )
    env = {"payload": payload, "sig": "bad", "binding_id": "bad"}
    assert verify_binding(env, kp, expected_domain="example.com", now=None) is False


def test_pqc_enforce_unknown_backend_raises() -> None:
    old = os.environ.get("QID_PQC_BACKEND")
    try:
        os.environ["QID_PQC_BACKEND"] = "unknown"
        try:
            pqc_backends.enforce_no_silent_fallback_for_alg(pqc_backends.ML_DSA_ALGO)
            assert False, "expected PQCBackendError"
        except pqc_backends.PQCBackendError:
            pass
    finally:
        if old is None:
            os.environ.pop("QID_PQC_BACKEND", None)
        else:
            os.environ["QID_PQC_BACKEND"] = old


def test_pqc_validate_oqs_module_rejects_invalid() -> None:
    class BadOQS:
        Signature = None  # not callable

    try:
        pqc_backends._validate_oqs_module(BadOQS())  # type: ignore[attr-defined]
        assert False, "expected PQCBackendError"
    except pqc_backends.PQCBackendError:
        pass


def test_pqc_verify_fail_closed_on_internal_exception() -> None:
    class DummySig:
        def __init__(self, alg: str):
            self.alg = alg

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def verify(self, msg: bytes, sig: bytes, pub: bytes) -> bool:
            raise RuntimeError("boom")

    class DummyOQS:
        Signature = DummySig

    old_import = pqc_backends._import_oqs
    try:
        pqc_backends._import_oqs = lambda: DummyOQS()  # type: ignore[assignment]
        ok = pqc_backends.liboqs_verify(pqc_backends.ML_DSA_ALGO, b"m", b"s", b"p")
        assert ok is False
    finally:
        pqc_backends._import_oqs = old_import  # type: ignore[assignment]


def test_qr_payload_roundtrip() -> None:
    raw = {
        "type": "login_request",
        "data": {"service_id": "s", "nonce": "n"},
    }
    payload = build_qr_payload(raw)  # <-- correct API: single dict argument
    parsed = parse_qr_payload(payload)
    assert parsed["type"] == "login_request"
    assert parsed["data"]["service_id"] == "s"
    assert parsed["data"]["nonce"] == "n"
