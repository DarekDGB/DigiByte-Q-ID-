from __future__ import annotations

import pytest

import qid.pqc_backends as pb
from qid.crypto import (
    DEV_ALGO,
    FALCON_ALGO,
    HYBRID_ALGO,
    ML_DSA_ALGO,
    generate_dev_keypair,
    generate_keypair,
    sign_payload,
    verify_payload,
)


class _Comp:
    def __init__(self, alg: str, public_key: str, secret_key: str | None):
        self.alg = alg
        self.public_key = public_key
        self.secret_key = secret_key


class _Container:
    def __init__(self, alg: str, ml: _Comp, fa: _Comp):
        self.alg = alg
        self.ml_dsa = ml
        self.falcon = fa


def test_generate_dev_keypair_exists_and_is_dev() -> None:
    kp = generate_dev_keypair()
    assert kp.algorithm == DEV_ALGO


def test_real_backend_non_hybrid_sign_and_verify_paths_are_exercised(monkeypatch) -> None:
    # Force "real backend selected" without needing oqs installed.
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    # Deterministic fake PQC sign/verify
    monkeypatch.setattr(pb, "liboqs_sign", lambda alg, msg, priv: b"SIG:" + alg.encode("ascii"))
    monkeypatch.setattr(pb, "liboqs_verify", lambda alg, msg, sig, pub: True)

    payload = {"type": "t", "n": 1}
    kp = generate_keypair(ML_DSA_ALGO)

    sig = sign_payload(payload, kp)
    assert isinstance(sig, str)

    ok = verify_payload(payload, sig, kp)
    assert ok is True


def test_real_backend_hybrid_requires_container_fail_closed(monkeypatch) -> None:
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    payload = {"type": "t", "n": 1}
    kp = generate_keypair(HYBRID_ALGO)

    with pytest.raises(pb.PQCBackendError):
        sign_payload(payload, kp, hybrid_container_b64=None)

    assert verify_payload(payload, "not-a-real-sig", kp, hybrid_container_b64=None) is False


def test_real_backend_hybrid_container_decode_fail_closed(monkeypatch) -> None:
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    import qid.hybrid_key_container as hkc

    monkeypatch.setattr(hkc, "try_decode_container", lambda b64: None)

    payload = {"type": "t", "n": 1}
    kp = generate_keypair(HYBRID_ALGO)

    with pytest.raises(pb.PQCBackendError):
        sign_payload(payload, kp, hybrid_container_b64="bad")


def test_real_backend_hybrid_container_alg_mismatch_fail_closed(monkeypatch) -> None:
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    import qid.hybrid_key_container as hkc

    c = _Container(
        alg="wrong",
        ml=_Comp(ML_DSA_ALGO, public_key="PUB_ML", secret_key="U0VD"),  # base64-ish
        fa=_Comp(FALCON_ALGO, public_key="PUB_FA", secret_key="U0VD"),
    )
    monkeypatch.setattr(hkc, "try_decode_container", lambda b64: c)

    payload = {"type": "t", "n": 1}
    kp = generate_keypair(HYBRID_ALGO)

    with pytest.raises(pb.PQCBackendError):
        sign_payload(payload, kp, hybrid_container_b64="any")


def test_real_backend_hybrid_container_missing_secret_keys_fail_closed(monkeypatch) -> None:
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    import qid.hybrid_key_container as hkc

    c = _Container(
        alg=HYBRID_ALGO,
        ml=_Comp(ML_DSA_ALGO, public_key="PUB_ML", secret_key=None),
        fa=_Comp(FALCON_ALGO, public_key="PUB_FA", secret_key=None),
    )
    monkeypatch.setattr(hkc, "try_decode_container", lambda b64: c)

    payload = {"type": "t", "n": 1}
    kp = generate_keypair(HYBRID_ALGO)

    with pytest.raises(pb.PQCBackendError):
        sign_payload(payload, kp, hybrid_container_b64="any")


def test_real_backend_hybrid_happy_path_is_exercised(monkeypatch) -> None:
    # Force backend and bypass oqs availability checks
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    # Fake liboqs sign/verify
    monkeypatch.setattr(pb, "liboqs_sign", lambda alg, msg, priv: b"S:" + alg.encode("ascii"))
    monkeypatch.setattr(pb, "liboqs_verify", lambda alg, msg, sig, pub: True)

    import qid.hybrid_key_container as hkc

    # Use valid base64 bytes for secrets/publics ("x" -> eA==)
    c = _Container(
        alg=HYBRID_ALGO,
        ml=_Comp(ML_DSA_ALGO, public_key="eA==", secret_key="eA=="),
        fa=_Comp(FALCON_ALGO, public_key="eA==", secret_key="eA=="),
    )
    monkeypatch.setattr(hkc, "try_decode_container", lambda b64: c)

    payload = {"type": "t", "n": 1}
    kp = generate_keypair(HYBRID_ALGO)

    sig = sign_payload(payload, kp, hybrid_container_b64="container")
    assert isinstance(sig, str)

    # Must verify with container in real-backend mode
    ok = verify_payload(payload, sig, kp, hybrid_container_b64="container")
    assert ok is True
