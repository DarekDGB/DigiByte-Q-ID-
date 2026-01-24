import os
import pytest

from qid.pqc.keygen_liboqs import (
    generate_ml_dsa_keypair,
    generate_falcon_keypair,
    PQCBackendError,
    PQCAlgorithmError,
)


def test_keygen_rejects_when_backend_not_enabled(monkeypatch):
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)
    with pytest.raises(PQCBackendError):
        generate_ml_dsa_keypair("ML-DSA-44")


def test_keygen_rejects_unknown_algorithm(monkeypatch):
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    with pytest.raises(PQCAlgorithmError):
        generate_ml_dsa_keypair("ML-DSA-999")


@pytest.mark.skipif(
    os.environ.get("QID_PQC_BACKEND") != "liboqs",
    reason="real liboqs backend not enabled",
)
def test_real_ml_dsa_keygen_produces_keys():
    pub, sec = generate_ml_dsa_keypair("ML-DSA-44")
    assert isinstance(pub, bytes)
    assert isinstance(sec, bytes)
    assert len(pub) > 0
    assert len(sec) > 0
