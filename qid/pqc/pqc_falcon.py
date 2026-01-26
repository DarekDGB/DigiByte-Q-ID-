from __future__ import annotations

from typing import Any


def _sign_with_signature(sig_obj: Any, msg: bytes, priv: bytes) -> bytes:
    """
    Sign message using a Signature instance, supporting multiple APIs:
    1) import_secret_key(priv) + sign(msg)   (real python-oqs/liboqs)
    2) sign(msg, priv)                       (some stubs)
    3) sign(msg)                             (if secret already bound)
    """
    if hasattr(sig_obj, "import_secret_key") and callable(getattr(sig_obj, "import_secret_key")):
        sig_obj.import_secret_key(priv)
        return bytes(sig_obj.sign(msg))

    try:
        return bytes(sig_obj.sign(msg, priv))
    except TypeError:
        return bytes(sig_obj.sign(msg))


def sign_falcon(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    """Falcon signing via oqs.Signature — may raise on backend errors."""
    alg = oqs_alg or "Falcon-512"

    signer = oqs.Signature(alg)

    if hasattr(signer, "__enter__") and hasattr(signer, "__exit__"):
        with signer as s:
            return _sign_with_signature(s, msg, priv)

    return _sign_with_signature(signer, msg, priv)


def verify_falcon(
    *, oqs: Any, msg: bytes, sig: bytes, pub: bytes, oqs_alg: str | None = None
) -> bool:
    """Falcon verify — must fail-closed (return False) on internal errors."""
    alg = oqs_alg or "Falcon-512"

    verifier = None
    try:
        verifier = oqs.Signature(alg)

        if hasattr(verifier, "__enter__") and hasattr(verifier, "__exit__"):
            with verifier as v:
                return bool(v.verify(msg, sig, pub))

        return bool(verifier.verify(msg, sig, pub))
    except Exception:
        return False
    finally:
        try:
            del verifier
        except Exception:
            pass
