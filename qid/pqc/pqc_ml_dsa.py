"""
ML-DSA (Dilithium family) signing/verification wrappers for python-oqs.

python-oqs API has changed across versions.
We use the "import key into Signature object" style:
- signer.import_secret_key(priv)
- signer.sign(msg)
- verifier.verify(msg, sig, pub)
"""

from __future__ import annotations

from typing import Any


def sign_ml_dsa(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str) -> bytes:
    with oqs.Signature(oqs_alg) as signer:
        # Newer python-oqs API: import the secret key first, then sign(msg)
        if hasattr(signer, "import_secret_key"):
            signer.import_secret_key(priv)  # type: ignore[attr-defined]
            return signer.sign(msg)
        # Back-compat (older python-oqs): signer.sign(msg, priv)
        return signer.sign(msg, priv)


def verify_ml_dsa(*, oqs: Any, msg: bytes, sig: bytes, pub: bytes, oqs_alg: str) -> bool:
    with oqs.Signature(oqs_alg) as verifier:
        # Most versions support verify(msg, sig, pub)
        return bool(verifier.verify(msg, sig, pub))
