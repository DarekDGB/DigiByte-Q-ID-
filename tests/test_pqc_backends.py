from __future__ import annotations

import os

import pytest

import qid.pqc_backends as pb
from qid.crypto import FALCON_ALGO, HYBRID_ALGO, ML_DSA_ALGO


def test_selected_backend_none_when_unset() -> None:
    os.environ.pop("QID_PQC_BACKEND", None)
    assert pb.selected_backend() is None


def test_selected_backend_liboqs_when_set() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"
    assert pb.selected_backend() == "liboqs"


def test_enforce_no_silent_fallback_blocks_pqc_algs_when_selected(monkeypatch: pytest.MonkeyPatch) -> None:
    # Deterministic even when oqs is installed (e.g. PQC Optional workflow).
    monkeypatch.setattr(pb, "oqs", None, raising=False)
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    with pytest.raises(pb.PQCBackendError):
        pb.enforce_no_silent_fallback_for_alg(ML_DSA_ALGO)

    with pytest.raises(pb.PQCBackendError):
        pb.enforce_no_silent_fallback_for_alg(FALCON_ALGO)

    with pytest.raises(pb.PQCBackendError):
        pb.enforce_no_silent_fallback_for_alg(HYBRID_ALGO)


def test_enforce_no_silent_fallback_allows_dev_algo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    pb.enforce_no_silent_fallback_for_alg("dev-hmac-sha256")
