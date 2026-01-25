from __future__ import annotations

from typing import Any


def sign_falcon(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    alg = oqs_alg or "Falcon-512"

    # IMPORTANT: create Signature inside the context manager to avoid pytest repr segfaults.
    with oqs.Signature(alg) as s:
        if hasattr(s, "import_secret_key"):
            s.import_secret_key(priv)  # type: ignore[attr-defined]
            return s.sign(msg)

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

    with oqs.Signature(alg) as v:
        if hasattr(v, "import_public_key"):
            v.import_public_key(pub)  # type: ignore[attr-defined]
            return bool(v.verify(msg, sig))

        try:
            return bool(v.verify(msg, sig, pub))
        except TypeError:
            return bool(v.verify(msg, sig))
