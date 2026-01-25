from __future__ import annotations

import base64
import os

import pytest

from qid.pqc.keygen_liboqs import generate_falcon_keypair, generate_ml_dsa_keypair


def _has_oqs() -> bool:
    try:
        import oqs  # noqa: F401
        return True
    except Exception:
        return False


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_ml_dsa_keygen_produces_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    # conftest clears QID_PQC_BACKEND for determinism; set it here explicitly.
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    pub, sec = generate_ml_dsa_keypair("ML-DSA-44")
    assert isinstance(pub, (bytes, bytearray)) and len(pub) > 0
    assert isinstance(sec, (bytes, bytearray)) and len(sec) > 0
    assert _b64u(bytes(pub))  # encodable


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_falcon_keygen_produces_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    pub, sec = generate_falcon_keypair("Falcon-512")
    assert isinstance(pub, (bytes, bytearray)) and len(pub) > 0
    assert isinstance(sec, (bytes, bytearray)) and len(sec) > 0
    assert _b64u(bytes(pub))  # encodable
