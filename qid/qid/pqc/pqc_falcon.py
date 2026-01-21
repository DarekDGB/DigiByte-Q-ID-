"""
Falcon wiring via liboqs.
"""

from __future__ import annotations

from typing import Any

OQS_ALG_FALCON_DEFAULT = "Falcon-512"


def sign_falcon(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str = OQS_ALG_FALCON_DEFAULT) -> bytes:
    with oqs.Signature(oqs_alg) as signer:
        return signer.sign(msg, priv)


def verify_falcon(*, oqs: Any, msg: bytes, sig: bytes, pub: bytes, oqs_alg: str = OQS_ALG_FALCON_DEFAULT) -> bool:
    with oqs.Signature(oqs_alg) as verifier:
        return bool(verifier.verify(msg, sig, pub))
