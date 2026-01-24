from __future__ import annotations

import pytest

import qid.protocol as pr
from qid.crypto import DEV_ALGO, generate_keypair
from qid.pqc_backends import PQCBackendError


def test_require_from_payload_rejects_non_string() -> None:
    with pytest.raises(ValueError):
        pr._require_from_payload({"require": 1})  # type: ignore[arg-type]


def test_require_from_payload_rejects_unknown_value() -> None:
    with pytest.raises(ValueError):
        pr._require_from_payload({"require": "nope"})


def test_build_login_response_payload_rejects_missing_service_id() -> None:
    with pytest.raises(ValueError):
        pr.build_login_response_payload({"nonce": "n1"}, address="A", pubkey="P")


def test_build_login_response_payload_rejects_missing_nonce() -> None:
    with pytest.raises(ValueError):
        pr.build_login_response_payload({"service_id": "s1"}, address="A", pubkey="P")


def test_sign_message_fail_closed_on_valueerror(monkeypatch: pytest.MonkeyPatch) -> None:
    kp = generate_keypair(DEV_ALGO)
    monkeypatch.setattr(pr, "sign_payload", lambda *a, **k: (_ for _ in ()).throw(ValueError("x")))
    msg = pr.sign_message({"x": 1}, kp)
    assert msg.signature == ""


def test_sign_message_fail_closed_on_pqcbackenderror(monkeypatch: pytest.MonkeyPatch) -> None:
    kp = generate_keypair(DEV_ALGO)
    monkeypatch.setattr(pr, "sign_payload", lambda *a, **k: (_ for _ in ()).throw(PQCBackendError("x")))
    msg = pr.sign_message({"x": 1}, kp)
    assert msg.signature == ""


def test_server_verify_login_response_fail_closed_on_type_mismatch() -> None:
    kp = generate_keypair(DEV_ALGO)
    req = pr.build_login_request_payload("svc", "n", "cb")
    resp = pr.build_login_response_payload(req, address="A", pubkey="P")
    resp["type"] = "not-login-response"
    assert pr.server_verify_login_response(req, resp, signature="sig", keypair=kp) is False


def test_server_verify_login_response_fail_closed_on_service_or_nonce_mismatch() -> None:
    kp = generate_keypair(DEV_ALGO)
    req = pr.build_login_request_payload("svc", "n", "cb")
    resp = pr.build_login_response_payload(req, address="A", pubkey="P")
    resp["service_id"] = "other"
    assert pr.server_verify_login_response(req, resp, signature="sig", keypair=kp) is False

    resp2 = pr.build_login_response_payload(req, address="A", pubkey="P")
    resp2["nonce"] = "other"
    assert pr.server_verify_login_response(req, resp2, signature="sig", keypair=kp) is False


def test_server_verify_login_response_fail_closed_on_require_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    kp = generate_keypair(DEV_ALGO)
    req = pr.build_login_request_payload("svc", "n", "cb")
    req["require"] = pr.REQUIRE_DUAL_PROOF
    resp = pr.build_login_response_payload(req, address="A", pubkey="P")
    resp["require"] = pr.REQUIRE_LEGACY  # mismatch
    assert pr.server_verify_login_response(req, resp, signature="sig", keypair=kp) is False


def test_server_verify_login_response_dual_proof_missing_binding_id_fails() -> None:
    kp = generate_keypair(DEV_ALGO)
    req = pr.build_login_request_payload("svc", "n", "cb")
    req["require"] = pr.REQUIRE_DUAL_PROOF
    resp = pr.build_login_response_payload(req, address="A", pubkey="P")
    # no binding_id
    assert pr.server_verify_login_response(req, resp, signature="sig", keypair=kp) is False


def test_server_verify_login_response_dual_proof_missing_or_bad_resolver_fails() -> None:
    kp = generate_keypair(DEV_ALGO)
    req = pr.build_login_request_payload("svc", "n", "cb")
    req["require"] = pr.REQUIRE_DUAL_PROOF
    resp = pr.build_login_response_payload(req, address="A", pubkey="P")
    resp["binding_id"] = "bid"

    # missing resolver
    assert pr.server_verify_login_response(req, resp, signature="sig", keypair=kp) is False

    # resolver not callable
    req2 = dict(req)
    req2["_binding_resolver"] = 123
    assert pr.server_verify_login_response(req2, resp, signature="sig", keypair=kp) is False


def test_server_verify_login_response_dual_proof_resolver_returns_none_fails() -> None:
    kp = generate_keypair(DEV_ALGO)
    req = pr.build_login_request_payload("svc", "n", "cb")
    req["require"] = pr.REQUIRE_DUAL_PROOF
    req["_binding_resolver"] = lambda bid: None
    resp = pr.build_login_response_payload(req, address="A", pubkey="P")
    resp["binding_id"] = "bid"
    assert pr.server_verify_login_response(req, resp, signature="sig", keypair=kp) is False


def test_server_verify_login_response_dual_proof_now_wrong_type_fails() -> None:
    kp = generate_keypair(DEV_ALGO)
    req = pr.build_login_request_payload("svc", "n", "cb")
    req["require"] = pr.REQUIRE_DUAL_PROOF
    req["_binding_resolver"] = lambda bid: {"payload": {}, "binding_id": "x", "sig": "y"}
    req["_now"] = "100"  # wrong type
    resp = pr.build_login_response_payload(req, address="A", pubkey="P")
    resp["binding_id"] = "bid"
    assert pr.server_verify_login_response(req, resp, signature="sig", keypair=kp) is False


def test_server_verify_login_response_dual_proof_binding_verify_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    kp = generate_keypair(DEV_ALGO)
    req = pr.build_login_request_payload("svc", "n", "cb")
    req["require"] = pr.REQUIRE_DUAL_PROOF
    req["_binding_resolver"] = lambda bid: {"payload": {}, "binding_id": "x", "sig": "y"}
    resp = pr.build_login_response_payload(req, address="A", pubkey="P")
    resp["binding_id"] = "bid"

    monkeypatch.setattr(pr, "verify_binding", lambda *a, **k: False)
    assert pr.server_verify_login_response(req, resp, signature="sig", keypair=kp) is False


def test_server_verify_login_response_dual_proof_pqc_verify_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    kp = generate_keypair(DEV_ALGO)
    req = pr.build_login_request_payload("svc", "n", "cb")
    req["require"] = pr.REQUIRE_DUAL_PROOF
    env = {"payload": {}, "binding_id": "x", "sig": "y"}
    req["_binding_resolver"] = lambda bid: env
    resp = pr.build_login_response_payload(req, address="A", pubkey="P")
    resp["binding_id"] = "bid"

    monkeypatch.setattr(pr, "verify_binding", lambda *a, **k: True)
    monkeypatch.setattr(pr._pqc_verify, "verify_pqc_login", lambda *a, **k: False)
    assert pr.server_verify_login_response(req, resp, signature="sig", keypair=kp) is False


def test_build_dual_proof_login_response_rejects_when_request_not_dual_proof() -> None:
    kp = generate_keypair(DEV_ALGO)
    req = pr.build_login_request_payload("svc", "n", "cb")
    # require defaults legacy
    with pytest.raises(ValueError):
        pr.build_dual_proof_login_response(
            request_payload=req,
            address="A",
            pubkey="P",
            legacy_keypair=kp,
            binding_id="bid",
            pqc_alg="pqc-ml-dsa",
            ml_dsa_keypair=kp,
        )


def test_build_dual_proof_login_response_rejects_empty_binding_id() -> None:
    kp = generate_keypair(DEV_ALGO)
    req = pr.build_login_request_payload("svc", "n", "cb")
    req["require"] = pr.REQUIRE_DUAL_PROOF
    with pytest.raises(ValueError):
        pr.build_dual_proof_login_response(
            request_payload=req,
            address="A",
            pubkey="P",
            legacy_keypair=kp,
            binding_id="",
            pqc_alg="pqc-ml-dsa",
            ml_dsa_keypair=kp,
        )
