from __future__ import annotations

from typing import Any


def sign_ml_dsa(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    """
    ML-DSA signing via python-oqs.

    Safety rule:
    - Never allow oqs.Signature objects to leak into exception context
      (pytest repr can segfault).
    """
    alg = oqs_alg or "Dilithium2"
    signer = None
    try:
        # Newer python-oqs supports providing secret_key in the ctor.
        try:
            with oqs.Signature(alg, secret_key=priv) as signer:  # type: ignore[call-arg]
                return signer.sign(msg)
        except TypeError:
            # Older API: construct without secret_key, then import or sign with priv.
            with oqs.Signature(alg) as signer:
                if hasattr(signer, "import_secret_key"):
                    signer.import_secret_key(priv)  # type: ignore[attr-defined]
                    return signer.sign(msg)
                try:
                    return signer.sign(msg, priv)
                except TypeError:
                    return signer.sign(msg)
    except Exception:
        try:
            del signer
        except Exception:
            pass
        raise RuntimeError("pqc_ml_dsa signing failed") from None


def verify_ml_dsa(*, oqs: Any, msg: bytes, sig: bytes, pub: bytes, oqs_alg: str | None = None) -> bool:
    """ML-DSA verify — fail closed."""
    alg = oqs_alg or "Dilithium2"
    verifier = None
    try:
        with oqs.Signature(alg) as verifier:
            return bool(verifier.verify(msg, sig, pub))
    except Exception:
        try:
            del verifier
        except Exception:
            pass
        return False
