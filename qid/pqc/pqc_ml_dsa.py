from __future__ import annotations

from typing import Any


def sign_ml_dsa(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    """ML-DSA signing via oqs.Signature — may raise on backend errors."""
    alg = oqs_alg or "ML-DSA-44"

    signer = oqs.Signature(alg)

    # Support both python-oqs styles:
    # - context manager (`with Signature(...) as s:`)
    # - plain object with `.sign()`
    if hasattr(signer, "__enter__") and hasattr(signer, "__exit__"):
        with signer as s:
            return bytes(s.sign(msg, priv))

    return bytes(signer.sign(msg, priv))


def verify_ml_dsa(
    *, oqs: Any, msg: bytes, sig: bytes, pub: bytes, oqs_alg: str | None = None
) -> bool:
    """ML-DSA verify — must fail-closed (return False) on internal errors."""
    alg = oqs_alg or "ML-DSA-44"

    verifier = None
    try:
        verifier = oqs.Signature(alg)

        # Support both newer python-oqs (context manager) and simple stubs used in tests.
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
