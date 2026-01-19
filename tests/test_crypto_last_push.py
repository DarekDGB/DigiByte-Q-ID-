import base64
import json
import pytest

from qid.crypto import QIDKeyPair, generate_keypair, sign_payload, verify_payload


def _b64_json(obj) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def test_generate_keypair_rejects_unknown_algorithm() -> None:
    with pytest.raises(ValueError):
        generate_keypair("no-such-alg")


def test_sign_payload_rejects_unknown_keypair_algorithm() -> None:
    kp = QIDKeyPair(algorithm="no-such-alg", secret_key="AA==", public_key="AA==")
    with pytest.raises(ValueError):
        sign_payload({"x": 1}, kp)


def test_verify_rejects_envelope_alg_not_string() -> None:
    # env["alg"] must be str => fail-closed False
    kp = generate_keypair()
    sig = _b64_json({"v": 1, "alg": 123, "sig": "AA=="})
    assert verify_payload({"x": 1}, sig, kp) is False


def test_verify_rejects_sig_field_not_string() -> None:
    # env["sig"] must be str for non-hybrid => fail-closed False
    kp = generate_keypair()
    sig = _b64_json({"v": 1, "alg": kp.algorithm, "sig": 123})
    assert verify_payload({"x": 1}, sig, kp) is False
