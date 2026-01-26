from __future__ import annotations

from typing import Any


def _sign_call(sig_obj: Any, msg: bytes, priv: bytes | None) -> bytes:
    """
    Try to sign with maximum compatibility across python-oqs / liboqs-python variants.
    """
    # Most common: sign(msg)
    try:
        return bytes(sig_obj.sign(msg))
    except TypeError:
        pass

    # Some variants: sign(msg, priv)
    if priv is not None:
        return bytes(sig_obj.sign(msg, priv))

    raise


def sign_ml_dsa(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    """ML-DSA signing via oqs.Signature — may raise on backend errors."""
    alg = oqs_alg or "ML-DSA-44"

    # Try modern constructor: Signature(alg, secret_key=priv)
    signer: Any
    priv_for_sign: bytes | None = None
    try:
        signer = oqs.Signature(alg, secret_key=priv)
        priv_for_sign = None
    except TypeError:
        # Fallback: Signature(alg) then import_secret_key(priv) if supported,
        # otherwise we'll try sign(msg, priv).
        signer = oqs.Signature(alg)
        if hasattr(signer, "import_secret_key"):
            signer.import_secret_key(priv)
            priv_for_sign = None
        else:
            priv_for_sign = priv

    if hasattr(signer, "__enter__") and hasattr(signer, "__exit__"):
        with signer as s:
            return _sign_call(s, msg, priv_for_sign)

    return _sign_call(signer, msg, priv_for_sign)


def verify_ml_dsa(
    *, oqs: Any, msg: bytes, sig: bytes, pub: bytes, oqs_alg: str | None = None
) -> bool:
    """ML-DSA verify via oqs.Signature — must return bool."""
    alg = oqs_alg or "ML-DSA-44"
    verifier = oqs.Signature(alg)

    if hasattr(verifier, "__enter__") and hasattr(verifier, "__exit__"):
        with verifier as v:
            return bool(v.verify(msg, sig, pub))

    return bool(verifier.verify(msg, sig, pub))
