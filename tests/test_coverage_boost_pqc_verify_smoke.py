from __future__ import annotations

import os
import types

import pytest

import qid.pqc_backends as pb
import qid.pqc_verify as pv


class _FakeSig:
    def __init__(self, alg, *args, **kwargs):
        self.alg = alg

    def verify(self, msg, sig, pub):
        return True


def test_verify_pqc_login_hybrid_nested_sig_dict_path(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force backend selection + fake oqs module
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    pb.oqs = types.SimpleNamespace(Signature=_FakeSig)

    binding_payload = {
        "type": "binding",
        "version": "1",
        "policy": "hybrid",
        "pqc_pubkeys": {
            "ml_dsa": "YQ",   # b"a"
            "falcon": "YQ",   # b"a"
        },
    }

    login_payload = {
        "pqc_alg": pb.HYBRID_ALGO,
        "pqc_sig": {"ml_dsa": "YQ", "falcon": "YQ"},
        "pqc_payload": binding_payload,
    }

    assert pv.verify_pqc_login(binding_payload, login_payload) is True
