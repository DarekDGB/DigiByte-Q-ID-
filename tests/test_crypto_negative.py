from __future__ import annotations

import pytest

import qid.crypto as c


def test_generate_keypair_rejects_unknown_alg() -> None:
    with pytest.raises(ValueError):
        c.generate_keypair("nope")


def test_generate_keypair_legacy_hybrid_normalizes() -> None:
    kp = c.generate_keypair("hybrid-dev-ml-dsa")
    assert kp.algorithm == c.HYBRID_ALGO


def test_envelope_decode_rejects_non_object_json() -> None:
    # base64("[]") -> valid JSON but not dict => ValueError
    sig = c._b64encode(b"[]")
    with pytest.raises(ValueError):
        c._envelope_decode(sig)


def test_verify_payload_rejects_invalid_envelope_base64() -> None:
    kp = c.generate_keypair(c.DEV_ALGO)
    assert c.verify_payload({"x": 1}, "not-base64!!", kp) is False


def test_verify_payload_rejects_wrong_envelope_version() -> None:
    kp = c.generate_keypair(c.DEV_ALGO)
    # Make an envelope with v != 1
    bad = c._envelope_encode({"v": 999, "alg": c.DEV_ALGO, "sig": c._b64encode(b"x")})
    assert c.verify_payload({"x": 1}, bad, kp) is False


def test_verify_payload_stub_dev_rejects_missing_sig_field() -> None:
    kp = c.generate_keypair(c.DEV_ALGO)
    env = c._envelope_encode({"v": 1, "alg": c.DEV_ALGO})  # missing 'sig'
    assert c.verify_payload({"x": 1}, env, kp) is False


def test_verify_payload_stub_pqc_rejects_missing_sig_field() -> None:
    kp = c.generate_keypair(c.ML_DSA_ALGO)
    env = c._envelope_encode({"v": 1, "alg": c.ML_DSA_ALGO})  # missing 'sig'
    assert c.verify_payload({"x": 1}, env, kp) is False


def test_verify_payload_stub_hybrid_rejects_non_dict_sigs() -> None:
    kp = c.generate_keypair(c.HYBRID_ALGO)
    env = c._envelope_encode({"v": 1, "alg": c.HYBRID_ALGO, "sigs": "nope"})
    assert c.verify_payload({"x": 1}, env, kp) is False


def test_verify_payload_stub_hybrid_rejects_bad_b64_in_sigs() -> None:
    kp = c.generate_keypair(c.HYBRID_ALGO)
    env = c._envelope_encode(
        {
            "v": 1,
            "alg": c.HYBRID_ALGO,
            "sigs": {c.ML_DSA_ALGO: "%%%NOTB64%%%", c.FALCON_ALGO: "AA"},
        }
    )
    assert c.verify_payload({"x": 1}, env, kp) is False


def test_stub_sign_hybrid_requires_64_bytes_secret() -> None:
    with pytest.raises(ValueError):
        c._stub_sign_hybrid(b"m", b"short")


def test_stub_verify_hybrid_false_when_secret_too_short() -> None:
    assert c._stub_verify_hybrid(b"m", b"short", {c.ML_DSA_ALGO: b"x", c.FALCON_ALGO: b"y"}) is False


def test_stub_verify_hybrid_false_when_keys_mismatch() -> None:
    secret = b"A" * 64
    assert c._stub_verify_hybrid(b"m", secret, {c.ML_DSA_ALGO: b"x"}) is False


def test_sign_payload_unknown_algorithm_rejected() -> None:
    kp = c.QIDKeyPair(algorithm="nope", secret_key=c._b64encode(b"A" * 32), public_key=c._b64encode(b"B" * 32))
    with pytest.raises(ValueError):
        c.sign_payload({"x": 1}, kp)


def test_sign_payload_stub_hybrid_ok_and_verify_roundtrip() -> None:
    kp = c.generate_keypair(c.HYBRID_ALGO)
    payload = {"x": 1}
    sig = c.sign_payload(payload, kp)
    assert c.verify_payload(payload, sig, kp) is True


def test_sign_payload_stub_hybrid_tamper_fails() -> None:
    kp = c.generate_keypair(c.HYBRID_ALGO)
    sig = c.sign_payload({"x": 1}, kp)
    assert c.verify_payload({"x": 2}, sig, kp) is False
