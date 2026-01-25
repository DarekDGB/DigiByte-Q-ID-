from __future__ import annotations

from typing import Any


def sign_falcon(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    alg = oqs_alg or "Falcon-512"
    signer = oqs.Signature(alg)

    if hasattr(signer, "import_secret_key"):
        with signer as s:
            s.import_secret_key(priv)  # type: ignore[attr-defined]
            return s.sign(msg)

    with signer as s:
        try:
            return s.sign(msg, priv)
        except TypeError:
            return s.sign(msg)


def verify_falcon(
    *,
    oqs: Any,
    msg: bytes,
    sig: bytes,
    pub: bytes,
    oqs_alg: str | None = None,
) -> bool:
    alg = oqs_alg or "Falcon-512"
    verifier = oqs.Signature(alg)

    if hasattr(verifier, "import_public_key"):
        with verifier as v:
            v.import_public_key(pub)  # type: ignore[attr-defined]
            return bool(v.verify(msg, sig))

    with verifier as v:
        try:
            return bool(v.verify(msg, sig, pub))
        except TypeError:
            return bool(v.verify(msg, sig))
