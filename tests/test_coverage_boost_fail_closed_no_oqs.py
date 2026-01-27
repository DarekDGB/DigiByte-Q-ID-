import pytest

from qid.pqc_verify import _b64url_decode, verify_pqc_login
from qid.pqc_verify import canonical_payload_bytes
from qid.crypto import generate_keypair, sign_payload, verify_payload, DEV_ALGO


def test_b64url_decode_rejects_non_str() -> None:
    with pytest.raises(ValueError):
        _b64url_decode(123)  # type: ignore[arg-type]


def test_b64url_decode_rejects_empty() -> None:
    with pytest.raises(ValueError):
        _b64url_decode("")


def test_verify_pqc_login_fail_closed_when_backend_not_selected() -> None:
    # No QID_PQC_BACKEND set => selected_backend() is None => must fail-closed
    binding = {"type": "binding", "version": "1", "policy": "ml-dsa", "pqc_pubkeys": {"ml_dsa": "YQ"}}
    login = {"pqc_alg": "pqc-ml-dsa", "pqc_sig": "YQ", "pqc_payload": binding}
    assert verify_pqc_login(binding, login) is False


def test_verify_pqc_login_rejects_mismatched_pqc_payload() -> None:
    # Backend not selected so result is False anyway, but this hits the mismatch branch early.
    binding = {"type": "binding", "version": "1", "policy": "hybrid", "pqc_pubkeys": {"ml_dsa": "YQ", "falcon": "YQ"}}
    other = {"type": "binding", "version": "1", "policy": "hybrid", "pqc_pubkeys": {"ml_dsa": "YQ", "falcon": "ZZ"}}
    login = {"pqc_alg": "pqc-hybrid-ml-dsa-falcon", "pqc_sig": {"ml_dsa": "YQ", "falcon": "YQ"}, "pqc_payload": other}
    assert verify_pqc_login(binding, login) is False


def test_crypto_envelope_rejects_garbage_signature() -> None:
    kp = generate_keypair(DEV_ALGO)
    assert verify_payload({"x": 1}, "not-base64", kp) is False


def test_crypto_envelope_rejects_wrong_version() -> None:
    kp = generate_keypair(DEV_ALGO)
    # Sign normally then mutate envelope version by decoding/recoding would be messy,
    # so we just craft a minimal valid base64 JSON envelope with wrong v.
    import base64, json
    env = {"v": 999, "alg": DEV_ALGO, "sig": base64.b64encode(b"xx").decode("ascii")}
    sig = base64.b64encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode("utf-8")).decode("ascii")
    assert verify_payload({"x": 1}, sig, kp) is False


def test_crypto_sign_and_verify_dev_happy_path_still_ok() -> None:
    # Safety check: we are not breaking normal behavior
    kp = generate_keypair(DEV_ALGO)
    payload = {"hello": "world"}
    sig = sign_payload(payload, kp)
    assert verify_payload(payload, sig, kp) is True
