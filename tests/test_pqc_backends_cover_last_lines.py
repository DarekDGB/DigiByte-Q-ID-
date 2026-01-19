import os
import pytest

import qid.pqc_backends as pb


def test_liboqs_sign_hits_scaffold_raise(monkeypatch) -> None:
    # Avoid failing at import-time so we reach the scaffold "not wired yet" raise
    monkeypatch.setattr(pb, "_import_oqs", lambda: object())

    with pytest.raises(pb.PQCBackendError):
        pb.liboqs_sign(pb.ML_DSA_ALGO, b"payload", b"priv")


def test_enforce_no_silent_fallback_hits_raise_block() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    with pytest.raises(pb.PQCBackendError):
        pb.enforce_no_silent_fallback_for_alg(pb.ML_DSA_ALGO)
