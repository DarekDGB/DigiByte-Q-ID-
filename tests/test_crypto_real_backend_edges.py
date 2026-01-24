from __future__ import annotations

import types
import pytest

import qid.crypto as c


def _kp(alg: str) -> c.QIDKeyPair:
    return c.generate_keypair(alg)


def test_sign_payload_real_backend_ml_dsa_path(monkeypatch: pytest.MonkeyPatch) -> None:
    kp = _kp(c.ML_DSA_ALGO)

    # Force "real backend selected" path without oqs installed
    monkeypatch.setattr(c, "sign_payload", c.sign_payload)  # ensure real function
    import qid.pqc_backends as pb
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)
    monkeypatch.setattr(pb, "liboqs_sign", lambda alg, msg, priv: b"SIG")

    sig = c.sign_payload({"x": 1}, kp)
    assert isinstance(sig, str) and sig


def test_sign_payload_real_backend_hybrid_requires_container(monkeypatch: pytest.MonkeyPatch) -> None:
    kp = _kp(c.HYBRID_ALGO)

    import qid.pqc_backends as pb
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    with pytest.raises(pb.PQCBackendError):
        c.sign_payload({"x": 1}, kp, hybrid_container_b64=None)


def test_sign_payload_real_backend_hybrid_container_decode_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    kp = _kp(c.HYBRID_ALGO)

    import qid.pqc_backends as pb
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    import qid.hybrid_key_container as hk
    monkeypatch.setattr(hk, "try_decode_container", lambda b64: None)

    with pytest.raises(pb.PQCBackendError):
        c.sign_payload({"x": 1}, kp, hybrid_container_b64="AA")


def test_sign_payload_real_backend_hybrid_container_alg_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    kp = _kp(c.HYBRID_ALGO)

    import qid.pqc_backends as pb
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    fake = types.SimpleNamespace(
        alg="not-hybrid",
        ml_dsa=types.SimpleNamespace(secret_key="AA", public_key="AA"),
        falcon=types.SimpleNamespace(secret_key="AA", public_key="AA"),
    )
    import qid.hybrid_key_container as hk
    monkeypatch.setattr(hk, "try_decode_container", lambda b64: fake)

    with pytest.raises(pb.PQCBackendError):
        c.sign_payload({"x": 1}, kp, hybrid_container_b64="AA")


def test_sign_payload_real_backend_hybrid_missing_secret_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    kp = _kp(c.HYBRID_ALGO)

    import qid.pqc_backends as pb
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    fake = types.SimpleNamespace(
        alg=c.HYBRID_ALGO,
        ml_dsa=types.SimpleNamespace(secret_key=None, public_key="AA"),
        falcon=types.SimpleNamespace(secret_key="AA", public_key="AA"),
    )
    import qid.hybrid_key_container as hk
    monkeypatch.setattr(hk, "try_decode_container", lambda b64: fake)

    with pytest.raises(pb.PQCBackendError):
        c.sign_payload({"x": 1}, kp, hybrid_container_b64="AA")


def test_verify_payload_real_backend_hybrid_requires_container_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    kp = _kp(c.HYBRID_ALGO)

    import qid.pqc_backends as pb
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)
    monkeypatch.setattr(pb, "liboqs_verify", lambda *a, **k: True)

    # Build a hybrid envelope (shape only)
    env = c._envelope_encode(
        {"v": 1, "alg": c.HYBRID_ALGO, "sigs": {c.ML_DSA_ALGO: c._b64encode(b"a"), c.FALCON_ALGO: c._b64encode(b"b")}}
    )

    assert c.verify_payload({"x": 1}, env, kp, hybrid_container_b64=None) is False


def test_verify_payload_real_backend_hybrid_container_wrong_alg_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    kp = _kp(c.HYBRID_ALGO)

    import qid.pqc_backends as pb
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)
    monkeypatch.setattr(pb, "liboqs_verify", lambda *a, **k: True)

    fake = types.SimpleNamespace(
        alg="not-hybrid",
        ml_dsa=types.SimpleNamespace(public_key="AA"),
        falcon=types.SimpleNamespace(public_key="AA"),
    )
    import qid.hybrid_key_container as hk
    monkeypatch.setattr(hk, "try_decode_container", lambda b64: fake)

    env = c._envelope_encode(
        {"v": 1, "alg": c.HYBRID_ALGO, "sigs": {c.ML_DSA_ALGO: c._b64encode(b"a"), c.FALCON_ALGO: c._b64encode(b"b")}}
    )
    assert c.verify_payload({"x": 1}, env, kp, hybrid_container_b64="AA") is False


def test_verify_payload_real_backend_hybrid_missing_sigs_dict_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    kp = _kp(c.HYBRID_ALGO)

    import qid.pqc_backends as pb
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    fake = types.SimpleNamespace(
        alg=c.HYBRID_ALGO,
        ml_dsa=types.SimpleNamespace(public_key="AA"),
        falcon=types.SimpleNamespace(public_key="AA"),
    )
    import qid.hybrid_key_container as hk
    monkeypatch.setattr(hk, "try_decode_container", lambda b64: fake)

    env = c._envelope_encode({"v": 1, "alg": c.HYBRID_ALGO, "sigs": "nope"})
    assert c.verify_payload({"x": 1}, env, kp, hybrid_container_b64="AA") is False
