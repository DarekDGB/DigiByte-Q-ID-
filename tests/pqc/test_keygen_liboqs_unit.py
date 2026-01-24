from __future__ import annotations

import types
import pytest

import qid.pqc.keygen_liboqs as kg


def test_require_liboqs_rejects_when_backend_not_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)
    with pytest.raises(kg.PQCBackendError):
        kg._require_liboqs()


def test_require_liboqs_rejects_when_oqs_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(kg, "oqs", None)
    with pytest.raises(kg.PQCBackendError):
        kg._require_liboqs()


def test_generate_ml_dsa_keypair_rejects_unknown_algorithm_even_if_oqs_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    # This test ensures algorithm allowlist is enforced (no silent accept)
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    class FakeOQS:
        class Signature:
            def __init__(self, alg: str):
                self.alg = alg
            def generate_keypair(self):
                return b"PUB"
            def export_secret_key(self):
                return b"SEC"

    monkeypatch.setattr(kg, "oqs", FakeOQS)

    with pytest.raises(kg.PQCAlgorithmError):
        kg.generate_ml_dsa_keypair("ML-DSA-999")


def test_generate_ml_dsa_keypair_success_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    class FakeSig:
        def __init__(self, alg: str):
            self.alg = alg
        def generate_keypair(self):
            return b"PUBKEY"
        def export_secret_key(self):
            return b"SECKEY"

    FakeOQS = types.SimpleNamespace(Signature=FakeSig)
    monkeypatch.setattr(kg, "oqs", FakeOQS)

    pub_b64u, sec_b64u = kg.generate_ml_dsa_keypair("ML-DSA-44")
    assert isinstance(pub_b64u, str) and pub_b64u
    assert isinstance(sec_b64u, str) and sec_b64u


def test_generate_ml_dsa_keypair_wraps_signature_ctor_typeerror(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    class BadSig:
        def __init__(self, alg: str):
            raise TypeError("boom")

    FakeOQS = types.SimpleNamespace(Signature=BadSig)
    monkeypatch.setattr(kg, "oqs", FakeOQS)

    with pytest.raises(kg.PQCBackendError):
        kg.generate_ml_dsa_keypair("ML-DSA-44")
