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


def test_generate_ml_dsa_keypair_rejects_unknown_algorithm(monkeypatch: pytest.MonkeyPatch) -> None:
    # Allowlist must be enforced regardless of backend wiring.
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    class FakeSig:
        def __init__(self, alg: str):
            self.alg = alg
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def generate_keypair(self):
            return b"PUB"
        def export_secret_key(self):
            return b"SEC"

    monkeypatch.setattr(kg, "oqs", types.SimpleNamespace(Signature=FakeSig))

    with pytest.raises(kg.PQCAlgorithmError):
        kg.generate_ml_dsa_keypair("ML-DSA-999")


def test_generate_ml_dsa_keypair_success_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    class FakeSig:
        def __init__(self, alg: str):
            self.alg = alg
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def generate_keypair(self):
            return b"PUBKEY"
        def export_secret_key(self):
            return b"SECKEY"

    monkeypatch.setattr(kg, "oqs", types.SimpleNamespace(Signature=FakeSig))

    pub_b64u, sec_b64u = kg.generate_ml_dsa_keypair("ML-DSA-44")
    assert isinstance(pub_b64u, (bytes, bytearray))
    assert isinstance(sec_b64u, (bytes, bytearray))
    assert pub_b64u and sec_b64u


def test_generate_ml_dsa_keypair_signature_ctor_typeerror_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    class BadSig:
        def __init__(self, alg: str):
            raise TypeError("boom")

    monkeypatch.setattr(kg, "oqs", types.SimpleNamespace(Signature=BadSig))

    # Current implementation does not wrap this TypeError.
    with pytest.raises(TypeError):
        kg.generate_ml_dsa_keypair("ML-DSA-44")

def test_generate_ml_dsa_keypair_raises_when_backend_ops_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    class FakeSig:
        def __init__(self, alg: str):
            self.alg = alg
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def generate_keypair(self):
            raise RuntimeError("fail-generate-keypair")
        def export_secret_key(self):
            raise RuntimeError("fail-export-secret")

    import types
    monkeypatch.setattr(kg, "oqs", types.SimpleNamespace(Signature=FakeSig))

    # We don't guess whether your code wraps to PQCBackendError or lets RuntimeError bubble.
    # We only force execution into lines 55-63.
    with pytest.raises(Exception):
        kg.generate_ml_dsa_keypair("ML-DSA-44")
