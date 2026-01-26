import os
import types
import builtins
import pytest

import qid.pqc_backends as pb
from qid.pqc.keygen_liboqs import (
    generate_falcon_keypair,
    generate_ml_dsa_keypair,
    PQCBackendError as KeygenBackendError,
    PQCAlgorithmError,
)
from qid.pqc.pqc_ml_dsa import sign_ml_dsa, verify_ml_dsa
from qid.pqc.pqc_falcon import sign_falcon, verify_falcon


# --------------------------------------------------------------------
# CRITICAL: no global state leaks (fixes your tests.yml failures)
# --------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_pqc_backend_state(monkeypatch: pytest.MonkeyPatch):
    """
    This module intentionally injects fake oqs modules for unit coverage.

    Guardrail:
    - NEVER leak pb.oqs into other tests, because other tests rely on oqs NOT being installed.
    - NEVER leak QID_PQC_BACKEND into other tests.

    We reset before/after every test.
    """
    # before
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)
    monkeypatch.setattr(pb, "oqs", pb._OQS_UNSET, raising=False)
    yield
    # after
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)
    monkeypatch.setattr(pb, "oqs", pb._OQS_UNSET, raising=False)


# -------------------------
# Helpers: fake oqs module
# -------------------------

class _FakeSigNewAPI:
    """Newer API: oqs.Signature(alg, secret_key=priv) works."""
    def __init__(self, alg, secret_key=None):
        self.alg = alg
        self.secret_key = secret_key

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def sign(self, msg, *args):
        return b"SIG:" + self.alg.encode("ascii") + b":" + msg

    def verify(self, msg, sig, pub):
        return sig == (b"SIG:" + self.alg.encode("ascii") + b":" + msg)

    def generate_keypair(self):
        return b"PUB:" + self.alg.encode("ascii")

    def export_secret_key(self):
        return b"SEC:" + self.alg.encode("ascii")


class _FakeSigOldAPI_ImportSecret:
    """
    Old API: Signature(alg, secret_key=...) raises TypeError,
    must call import_secret_key then sign(msg).
    """
    def __init__(self, alg, secret_key=None):
        if secret_key is not None:
            raise TypeError("old api: no secret_key kwarg")
        self.alg = alg

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def import_secret_key(self, priv):
        self._sec = priv

    def sign(self, msg, *args):
        return b"SIGI:" + self.alg.encode("ascii") + b":" + msg

    def verify(self, msg, sig, pub):
        return sig == (b"SIGI:" + self.alg.encode("ascii") + b":" + msg)

    def generate_keypair(self):
        return b"PUB:" + self.alg.encode("ascii")

    def export_secret_key(self):
        return b"SEC:" + self.alg.encode("ascii")


class _FakeSigOldAPI_SignWithPriv:
    """
    Old API: Signature(alg, secret_key=...) raises TypeError,
    no import_secret_key, but signer.sign(msg, priv) works.
    """
    def __init__(self, alg, secret_key=None):
        if secret_key is not None:
            raise TypeError("old api: no secret_key kwarg")
        self.alg = alg

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def sign(self, msg, priv=None):
        if priv is None:
            raise TypeError("needs priv in this fake")
        return b"SIGP:" + self.alg.encode("ascii") + b":" + msg

    def verify(self, msg, sig, pub):
        return sig == (b"SIGP:" + self.alg.encode("ascii") + b":" + msg)

    def generate_keypair(self):
        return b"PUB:" + self.alg.encode("ascii")

    def export_secret_key(self):
        return b"SEC:" + self.alg.encode("ascii")


def _fake_oqs(SignatureClass):
    return types.SimpleNamespace(Signature=SignatureClass)


# -------------------------
# pqc_ml_dsa / pqc_falcon unit coverage (no real oqs)
# -------------------------

def test_pqc_ml_dsa_sign_new_api_path() -> None:
    oqs = _fake_oqs(_FakeSigNewAPI)
    sig = sign_ml_dsa(oqs=oqs, msg=b"m", priv=b"p", oqs_alg="ML-DSA-44")
    assert sig.startswith(b"SIG:ML-DSA-44:")


def test_pqc_ml_dsa_sign_old_api_import_secret_key_path() -> None:
    oqs = _fake_oqs(_FakeSigOldAPI_ImportSecret)
    sig = sign_ml_dsa(oqs=oqs, msg=b"m", priv=b"p", oqs_alg="Dilithium2")
    assert sig.startswith(b"SIGI:Dilithium2:")


def test_pqc_ml_dsa_sign_old_api_sign_with_priv_path() -> None:
    oqs = _fake_oqs(_FakeSigOldAPI_SignWithPriv)
    sig = sign_ml_dsa(oqs=oqs, msg=b"m", priv=b"p", oqs_alg="Dilithium2")
    assert sig.startswith(b"SIGP:Dilithium2:")


def test_pqc_ml_dsa_verify_fail_closed_on_exception() -> None:
    class BoomSig(_FakeSigNewAPI):
        def verify(self, msg, sig, pub):
            raise RuntimeError("boom")

    oqs = _fake_oqs(BoomSig)
    assert verify_ml_dsa(oqs=oqs, msg=b"m", sig=b"s", pub=b"p", oqs_alg="ML-DSA-44") is False


def test_pqc_falcon_sign_new_api_path() -> None:
    oqs = _fake_oqs(_FakeSigNewAPI)
    sig = sign_falcon(oqs=oqs, msg=b"m", priv=b"p", oqs_alg="Falcon-512")
    assert sig.startswith(b"SIG:Falcon-512:")


def test_pqc_falcon_verify_fail_closed_on_exception() -> None:
    class BoomSig(_FakeSigNewAPI):
        def verify(self, msg, sig, pub):
            raise RuntimeError("boom")

    oqs = _fake_oqs(BoomSig)
    assert verify_falcon(oqs=oqs, msg=b"m", sig=b"s", pub=b"p", oqs_alg="Falcon-512") is False


# -------------------------
# keygen_liboqs unit coverage (no real oqs)
# -------------------------

def test_keygen_rejects_invalid_algorithms() -> None:
    with pytest.raises(PQCAlgorithmError):
        generate_ml_dsa_keypair("NOT-ALLOWED")
    with pytest.raises(PQCAlgorithmError):
        generate_falcon_keypair("NOT-ALLOWED")


def test_keygen_requires_backend_selected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)
    with pytest.raises(KeygenBackendError):
        generate_ml_dsa_keypair("ML-DSA-44")


def test_keygen_uses_fallback_name_when_primary_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    class SigSelect:
        def __init__(self, alg):
            if alg == "ML-DSA-44":
                raise RuntimeError("unsupported name in this fake")
            self.alg = alg

        def __enter__(self): return self
        def __exit__(self, exc_type, exc, tb): return False

        def generate_keypair(self):
            return b"PUB:" + self.alg.encode("ascii")

        def export_secret_key(self):
            return b"SEC:" + self.alg.encode("ascii")

    import qid.pqc.keygen_liboqs as kg
    monkeypatch.setattr(kg, "oqs", types.SimpleNamespace(Signature=SigSelect))

    pub, sec = generate_ml_dsa_keypair("ML-DSA-44")
    assert pub.startswith(b"PUB:Dilithium2")
    assert sec.startswith(b"SEC:Dilithium2")


# -------------------------
# pqc_backends coverage: injected module path + import failure + propagation
# -------------------------

def test_pqc_backends_import_oqs_uses_injected_cached_module(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pb, "oqs", types.SimpleNamespace(Signature=_FakeSigNewAPI))
    mod = pb._import_oqs()
    assert getattr(mod, "Signature") is _FakeSigNewAPI


def test_pqc_backends_import_oqs_raises_when_real_import_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pb, "oqs", pb._OQS_UNSET, raising=False)

    real_import = builtins.__import__

    def boom_import(name, *args, **kwargs):
        if name == "oqs":
            raise ImportError("no oqs here")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", boom_import)
    with pytest.raises(pb.PQCBackendError):
        pb._import_oqs()


def test_pqc_backends_liboqs_sign_propagates_backend_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pb, "oqs", types.SimpleNamespace(Signature=_FakeSigNewAPI))

    import qid.pqc.pqc_ml_dsa as ml
    monkeypatch.setattr(ml, "sign_ml_dsa", lambda **kw: (_ for _ in ()).throw(pb.PQCBackendError("x")))

    with pytest.raises(pb.PQCBackendError):
        pb.liboqs_sign(pb.ML_DSA_ALGO, b"m", b"priv")


def test_pqc_backends_liboqs_verify_propagates_backend_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pb, "oqs", types.SimpleNamespace(Signature=_FakeSigNewAPI))

    import qid.pqc.pqc_ml_dsa as ml
    monkeypatch.setattr(ml, "verify_ml_dsa", lambda **kw: (_ for _ in ()).throw(pb.PQCBackendError("x")))

    with pytest.raises(pb.PQCBackendError):
        pb.liboqs_verify(pb.ML_DSA_ALGO, b"m", b"s", b"p")
