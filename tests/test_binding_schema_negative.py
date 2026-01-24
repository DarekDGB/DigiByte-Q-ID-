from __future__ import annotations

import pytest

from qid.binding import validate_binding_payload, verify_binding
from qid.crypto import DEV_ALGO, generate_keypair


def test_normalize_domain_type_error_path() -> None:
    from qid.binding import normalize_domain

    with pytest.raises(TypeError):
        normalize_domain(123)  # type: ignore[arg-type]


def test_validate_binding_payload_rejects_non_mapping() -> None:
    with pytest.raises(TypeError):
        validate_binding_payload("x")  # type: ignore[arg-type]


def test_validate_binding_payload_rejects_wrong_version() -> None:
    with pytest.raises(ValueError):
        validate_binding_payload(
            {
                "version": "0",
                "type": "binding",
                "domain": "example.com",
                "address": "ADDR",
                "policy": "ml-dsa",
                "pqc_pubkeys": {"ml_dsa": "AA", "falcon": None},
                "created_at": 1,
            }
        )


def test_validate_binding_payload_rejects_wrong_type_field() -> None:
    with pytest.raises(ValueError):
        validate_binding_payload(
            {
                "version": "1",
                "type": "nope",
                "domain": "example.com",
                "address": "ADDR",
                "policy": "ml-dsa",
                "pqc_pubkeys": {"ml_dsa": "AA", "falcon": None},
                "created_at": 1,
            }
        )


def test_validate_binding_payload_rejects_empty_domain_or_address() -> None:
    with pytest.raises(ValueError):
        validate_binding_payload(
            {
                "version": "1",
                "type": "binding",
                "domain": "",
                "address": "ADDR",
                "policy": "ml-dsa",
                "pqc_pubkeys": {"ml_dsa": "AA", "falcon": None},
                "created_at": 1,
            }
        )
    with pytest.raises(ValueError):
        validate_binding_payload(
            {
                "version": "1",
                "type": "binding",
                "domain": "example.com",
                "address": "",
                "policy": "ml-dsa",
                "pqc_pubkeys": {"ml_dsa": "AA", "falcon": None},
                "created_at": 1,
            }
        )


def test_validate_binding_payload_rejects_bad_policy() -> None:
    with pytest.raises(ValueError):
        validate_binding_payload(
            {
                "version": "1",
                "type": "binding",
                "domain": "example.com",
                "address": "ADDR",
                "policy": "bad",
                "pqc_pubkeys": {"ml_dsa": "AA", "falcon": None},
                "created_at": 1,
            }
        )


def test_validate_binding_payload_rejects_pqc_pubkeys_wrong_type() -> None:
    with pytest.raises(ValueError):
        validate_binding_payload(
            {
                "version": "1",
                "type": "binding",
                "domain": "example.com",
                "address": "ADDR",
                "policy": "ml-dsa",
                "pqc_pubkeys": "nope",
                "created_at": 1,
            }
        )


def test_validate_binding_payload_requires_keys_by_policy() -> None:
    # ml-dsa requires ml_dsa string
    with pytest.raises(ValueError):
        validate_binding_payload(
            {
                "version": "1",
                "type": "binding",
                "domain": "example.com",
                "address": "ADDR",
                "policy": "ml-dsa",
                "pqc_pubkeys": {"ml_dsa": None, "falcon": None},
                "created_at": 1,
            }
        )
    # falcon requires falcon string
    with pytest.raises(ValueError):
        validate_binding_payload(
            {
                "version": "1",
                "type": "binding",
                "domain": "example.com",
                "address": "ADDR",
                "policy": "falcon",
                "pqc_pubkeys": {"ml_dsa": None, "falcon": None},
                "created_at": 1,
            }
        )


def test_validate_binding_payload_rejects_created_at_wrong_type() -> None:
    with pytest.raises(TypeError):
        validate_binding_payload(
            {
                "version": "1",
                "type": "binding",
                "domain": "example.com",
                "address": "ADDR",
                "policy": "ml-dsa",
                "pqc_pubkeys": {"ml_dsa": "AA", "falcon": None},
                "created_at": "1",
            }
        )


def test_validate_binding_payload_rejects_expires_at_wrong_type() -> None:
    with pytest.raises(TypeError):
        validate_binding_payload(
            {
                "version": "1",
                "type": "binding",
                "domain": "example.com",
                "address": "ADDR",
                "policy": "ml-dsa",
                "pqc_pubkeys": {"ml_dsa": "AA", "falcon": None},
                "created_at": 1,
                "expires_at": "2",
            }
        )


def test_verify_binding_fail_closed_on_bad_envelope_shapes() -> None:
    kp = generate_keypair(DEV_ALGO)

    # envelope not mapping
    assert verify_binding("x", kp, expected_domain="example.com", now=1) is False  # type: ignore[arg-type]

    # payload not mapping
    assert verify_binding({"binding_id": "x", "payload": 1, "sig": "s"}, kp, expected_domain="example.com", now=1) is False

    # binding_id empty
    assert verify_binding({"binding_id": "", "payload": {}, "sig": "s"}, kp, expected_domain="example.com", now=1) is False

    # signature empty (both fields)
    assert verify_binding({"binding_id": "x", "payload": {}, "sig": ""}, kp, expected_domain="example.com", now=1) is False
