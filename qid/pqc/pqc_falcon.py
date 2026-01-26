from __future__ import annotations

from typing import Any

from qid.pqc.pqc_ml_dsa import _set_secret_key


def sign_falcon(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    """
    Falcon signing via python-oqs.

    Safety rule:
    - Never allow oqs.Signature objects to leak into exception context
      (pytest repr can segfault).
    """
    alg = oqs_alg or "Falcon-512"
    signer = None
    try:
        # Try ctor-based secret key injection (newer API variants).
        for ctor_kwargs in ({"secret_key": priv}, {"sk": priv}):
            try:
                with oqs.Signature(alg, **ctor_kwargs) as signer:  # type: ignore[call-arg]
                    try:
                        sig = signer.sign(msg)
                    except TypeError:
                        sig = signer.sign(msg, priv)
                    if sig is None:
                        raise RuntimeError("signer.sign() returned None")
                    return sig
            except TypeError:
                # Signature ctor doesn't accept those kwargs.
                pass

        # Older API: construct without secret key, then import/set, then sign.
        with oqs.Signature(alg) as signer:
            _set_secret_key(signer, priv)
            try:
                sig = signer.sign(msg)
            except TypeError:
                sig = signer.sign(msg, priv)
            if sig is None:
                raise RuntimeError("signer.sign() returned None")
            return sig

    except Exception:
        try:
            del signer
        except Exception:
            pass
        raise RuntimeError("pqc_falcon signing failed") from None


def verify_falcon(*, oqs: Any, msg: bytes, sig: bytes, pub: bytes, oqs_alg: str | None = None) -> bool:
    """Falcon verify — fail closed."""
    alg = oqs_alg or "Falcon-512"
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
