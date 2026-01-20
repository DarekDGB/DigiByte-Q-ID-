"""
MIT License
Copyright (c) 2025 DarekDGB
"""

from __future__ import annotations

import pytest

from qid.crypto import FALCON_ALGO, HYBRID_ALGO, ML_DSA_ALGO
from qid.hybrid_key_container import (
    build_container,
    decode_container,
    encode_container,
    public_view_dict,
    to_dict,
    try_decode_container,
)
from qid.qr_payloads import build_qr_payload, parse_qr_payload


def test_qr_payload_wrappers_roundtrip() -> None:
    payload = {
        "type": "login_request",
        "service_id": "svc",
        "nonce": "n",
        "callback_url": "https://cb",
        "version": "1",
    }
    uri = build_qr_payload(payload)
    out = parse_qr_payload(uri)
    assert out["service_id"] == "svc"
    assert out["nonce"] == "n"


def test_container_to_dict_includes_secret_keys_when_present() -> None:
    c = build_container(
        kid="kid-secret",
        ml_dsa_public_key="PUB_ML",
        falcon_public_key="PUB_FA",
        ml_dsa_secret_key="SECRET_ML",
        falcon_secret_key="SECRET_FA",
    )
    d = to_dict(c)
    assert d["ml_dsa"]["secret_key"] == "SECRET_ML"
    assert d["falcon"]["secret_key"] == "SECRET_FA"


def test_decode_container_rejects_invalid_base64_and_invalid_json() -> None:
    with pytest.raises(ValueError):
        decode_container("***")  # invalid base64 => must raise ValueError

    # valid base64 but invalid JSON bytes => must raise ValueError
    with pytest.raises(ValueError):
        decode_container("ew==")  # base64("{") -> invalid JSON


def test_try_decode_container_accepts_mapping_input() -> None:
    c = build_container("kid1", "PUB_ML", "PUB_FA")
    d = to_dict(c)
    out = try_decode_container(d)
    assert out is not None
    assert out.kid == "kid1"


def test_public_view_dict_accepts_b64_and_object_and_strips_secrets() -> None:
    c = build_container(
        kid="kid2",
        ml_dsa_public_key="PUB_ML",
        falcon_public_key="PUB_FA",
        ml_dsa_secret_key="SECRET_ML",
        falcon_secret_key="SECRET_FA",
    )
    b64 = encode_container(c)

    pv1 = public_view_dict(b64)
    pv2 = public_view_dict(c)

    assert pv1["kid"] == "kid2"
    assert pv2["kid"] == "kid2"

    # must never leak secret keys
    assert "secret_key" not in pv1["ml_dsa"]
    assert "secret_key" not in pv1["falcon"]
    assert "secret_key" not in pv2["ml_dsa"]
    assert "secret_key" not in pv2["falcon"]


def test_build_container_guardrails_negative_paths() -> None:
    # unexpected kwarg
    with pytest.raises(TypeError):
        build_container(kid="kid", ml_dsa_public_key="PUB_ML", falcon_public_key="PUB_FA", nope=1)

    # wrong alg
    with pytest.raises(ValueError):
        build_container(kid="kid", ml_dsa_public_key="PUB_ML", falcon_public_key="PUB_FA", alg="wrong-alg")

    # missing kid
    with pytest.raises(ValueError):
        build_container(ml_dsa_public_key="PUB_ML", falcon_public_key="PUB_FA")  # type: ignore[call-arg]

    # missing pubkeys
    with pytest.raises(ValueError):
        build_container(kid="kid")  # type: ignore[call-arg]

    # secret key wrong types
    with pytest.raises(ValueError):
        build_container(
            kid="kid",
            ml_dsa_public_key="PUB_ML",
            falcon_public_key="PUB_FA",
            ml_dsa_secret_key=123,  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError):
        build_container(
            kid="kid",
            ml_dsa_public_key="PUB_ML",
            falcon_public_key="PUB_FA",
            falcon_secret_key=123,  # type: ignore[arg-type]
        )


def test_encode_container_rejects_secret_key_wrong_type_in_dict() -> None:
    good = build_container("kid1", "PUB_ML", "PUB_FA")
    d = {
        "v": 1,
        "alg": HYBRID_ALGO,
        "kid": "kid1",
        "ml_dsa": {"alg": ML_DSA_ALGO, "public_key": good.ml_dsa.public_key, "secret_key": "OK"},
        "falcon": {"alg": FALCON_ALGO, "public_key": good.falcon.public_key, "secret_key": 123},
        "container_hash": good.container_hash,
    }
    with pytest.raises(ValueError):
        encode_container(d)  # must validate secret_key types
