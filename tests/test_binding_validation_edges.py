from __future__ import annotations

from qid.binding import (
    build_binding_payload,
    compute_binding_id,
    sign_binding,
    validate_binding_payload,
    verify_binding,
)
from qid.crypto import DEV_ALGO, generate_keypair


def test_normalize_domain_rejects_scheme_and_path() -> None:
    kp = generate_keypair(DEV_ALGO)

    # scheme should be rejected at build time
    try:
        _ = build_binding_payload(
            domain="https://example.com",
            address="ADDR",
            policy="ml-dsa",
            ml_dsa_pub_b64u="ml",
            falcon_pub_b64u=None,
            created_at=1,
            expires_at=None,
        )
        assert False, "expected ValueError"
    except ValueError:
        pass

    # path should be rejected at build time
    try:
        _ = build_binding_payload(
            domain="example.com/login",
            address="ADDR",
            policy="ml-dsa",
            ml_dsa_pub_b64u="ml",
            falcon_pub_b64u=None,
            created_at=1,
            expires_at=None,
        )
        assert False, "expected ValueError"
    except ValueError:
        pass

    # sanity: valid domain still works
    payload = build_binding_payload(
        domain="Example.COM",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="ml",
        falcon_pub_b64u=None,
        created_at=1,
        expires_at=None,
    )
    env = sign_binding(payload, kp)
    assert verify_binding(env, kp, expected_domain="example.com", now=2) is True


def test_validate_binding_payload_rejects_invalid_policy() -> None:
    payload = {
        "version": "1",
        "type": "binding",
        "domain": "example.com",
        "address": "ADDR",
        "policy": "nope",
        "pqc_pubkeys": {"ml_dsa": "ml", "falcon": None},
        "created_at": 1,
        "expires_at": None,
    }
    try:
        validate_binding_payload(payload)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_policy_requires_matching_pqc_keys() -> None:
    # ml-dsa policy requires ml_dsa key
    payload = {
        "version": "1",
        "type": "binding",
        "domain": "example.com",
        "address": "ADDR",
        "policy": "ml-dsa",
        "pqc_pubkeys": {"ml_dsa": None, "falcon": None},
        "created_at": 1,
        "expires_at": None,
    }
    try:
        validate_binding_payload(payload)
        assert False, "expected ValueError"
    except ValueError:
        pass

    # falcon policy requires falcon key
    payload2 = dict(payload)
    payload2["policy"] = "falcon"
    payload2["pqc_pubkeys"] = {"ml_dsa": None, "falcon": None}
    try:
        validate_binding_payload(payload2)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_validate_rejects_expires_at_wrong_type() -> None:
    payload = {
        "version": "1",
        "type": "binding",
        "domain": "example.com",
        "address": "ADDR",
        "policy": "ml-dsa",
        "pqc_pubkeys": {"ml_dsa": "ml", "falcon": None},
        "created_at": 1,
        "expires_at": "99",
    }
    try:
        validate_binding_payload(payload)
        assert False, "expected TypeError"
    except TypeError:
        pass


def test_verify_binding_rejects_binding_id_mismatch() -> None:
    kp = generate_keypair(DEV_ALGO)
    payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="ml",
        falcon_pub_b64u=None,
        created_at=10,
        expires_at=None,
    )
    env = sign_binding(payload, kp)

    # force a mismatched binding_id
    bad = dict(env)
    bad["binding_id"] = compute_binding_id(dict(payload, domain="evil.com"))  # type: ignore[arg-type]
    assert verify_binding(bad, kp, expected_domain="example.com", now=11) is False


def test_verify_binding_rejects_empty_signature() -> None:
    kp = generate_keypair(DEV_ALGO)
    payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="ml",
        falcon_pub_b64u=None,
        created_at=10,
        expires_at=None,
    )
    env = sign_binding(payload, kp)

    bad = dict(env)
    bad["sig"] = ""
    assert verify_binding(bad, kp, expected_domain="example.com", now=11) is False


def test_verify_binding_accepts_legacy_signature_field() -> None:
    kp = generate_keypair(DEV_ALGO)
    payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="ml",
        falcon_pub_b64u=None,
        created_at=10,
        expires_at=None,
    )
    env = sign_binding(payload, kp)

    # Move sig -> signature (legacy compatibility)
    legacy = dict(env)
    legacy["signature"] = legacy.pop("sig")
    assert verify_binding(legacy, kp, expected_domain="example.com", now=11) is True
