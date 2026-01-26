from __future__ import annotations

from typing import Any


def sign_falcon(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    """Falcon signing via oqs.Signature — may raise on backend errors."""
    alg = oqs_alg or "Falcon-512"

    signer = oqs.Signature(alg)

    if hasattr(signer, "__enter__") and hasattr(signer, "__exit__"):
        with signer as s:
            return bytes(s.sign(msg, priv))

    return bytes(signer.sign(msg, priv))


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
