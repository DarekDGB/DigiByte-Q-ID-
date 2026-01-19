from __future__ import annotations

import qid.pqc_backends as pb
from qid.crypto import HYBRID_ALGO, generate_keypair
from qid.protocol import sign_message, verify_message


def test_protocol_stub_hybrid_does_not_require_container() -> None:
    # default stub mode (no backend selected)
    kp = generate_keypair(HYBRID_ALGO)
    payload = {"type": "t", "n": 1}
    msg = sign_message(payload, kp)
    assert verify_message(msg, kp) is True


def test_protocol_real_backend_hybrid_requires_container(monkeypatch) -> None:
    # simulate backend selected so hybrid requires container
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)
    monkeypatch.setattr(pb, "liboqs_sign", lambda alg, msg, priv: b"S:" + alg.encode("ascii"))
    monkeypatch.setattr(pb, "liboqs_verify", lambda alg, msg, sig, pub: True)

    import qid.hybrid_key_container as hkc

    class _Comp:
        def __init__(self, public_key: str, secret_key: str | None):
            self.public_key = public_key
            self.secret_key = secret_key

    class _Container:
        def __init__(self):
            self.alg = HYBRID_ALGO
            self.ml_dsa = _Comp("eA==", "eA==")
            self.falcon = _Comp("eA==", "eA==")

    monkeypatch.setattr(hkc, "try_decode_container", lambda b64: _Container())

    kp = generate_keypair(HYBRID_ALGO)
    payload = {"type": "t", "n": 1}

    # With container -> sign+verify works
    msg = sign_message(payload, kp, hybrid_container_b64="container")
    assert verify_message(msg, kp) is True

    # Without container -> must fail-closed on verify
    msg2 = sign_message(payload, kp, hybrid_container_b64=None)  # may raise at sign time depending on backend logic
    assert verify_message(msg2, kp) is False
