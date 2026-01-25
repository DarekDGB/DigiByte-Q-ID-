"""
Falcon signing/verification wrappers for python-oqs.

python-oqs API has changed across versions.
We prefer:
- signer.import_secret_key(priv)
- signer.sign(msg)
"""

from __future__ import annotations

from typing import Any


def sign_falcon(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str) -> bytes:
    with oqs.Signature(oqs_alg) as signer:
        if hasattr(signer, "import_secret_key"):
            signer.import_secret_key(priv)  # type: ignore[attr-defined]
            return signer.sign(msg)
        return signer.sign(msg, priv)


def verify_falcon(*, oqs: Any, msg: bytes, sig: bytes, pub: bytes, oqs_alg: str) -> bool:
    with oqs.Signature(oqs_alg) as verifier:
        return bool(verifier.verify(msg, sig, pub))
