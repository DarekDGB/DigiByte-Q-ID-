from __future__ import annotations

from typing import Any


def sign_ml_dsa(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    alg = oqs_alg or "Dilithium2"

    # IMPORTANT: create Signature inside the context manager to avoid pytest repr segfaults
    # when liboqs-python objects leak into locals.
    with oqs.Signature(alg) as s:
        # Newer python-oqs: import_secret_key + sign(msg)
        if hasattr(s, "import_secret_key"):
            s.import_secret_key(priv)  # type: ignore[attr-defined]
            return s.sign(msg)

        # Dummy / older API: sign(msg, priv) or sign(msg)
        try:
            return s.sign(msg, priv)
        except TypeError:
            return s.sign(msg)


def verify_ml_dsa(
    *,
    oqs: Any,
    msg: bytes,
    sig: bytes,
    pub: bytes,
    oqs_alg: str | None = None,
) -> bool:
    alg = oqs_alg or "Dilithium2"

    # IMPORTANT: same rule — never keep Signature instance in locals.
    with oqs.Signature(alg) as v:
        if hasattr(v, "import_public_key"):
            v.import_public_key(pub)  # type: ignore[attr-defined]
            return bool(v.verify(msg, sig))

        try:
            return bool(v.verify(msg, sig, pub))
        except TypeError:
            return bool(v.verify(msg, sig))
