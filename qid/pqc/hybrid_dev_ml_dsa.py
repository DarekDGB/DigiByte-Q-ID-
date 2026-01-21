from __future__ import annotations

from typing import Any, Tuple

from .pqc_ml_dsa import sign_ml_dsa, verify_ml_dsa
from .pqc_falcon import sign_falcon, verify_falcon


def sign_hybrid_strict_and(
    *, oqs: Any, msg: bytes, ml_dsa_priv: bytes, falcon_priv: bytes, ml_dsa_alg: str, falcon_alg: str
) -> Tuple[bytes, bytes]:
    sig_ml = sign_ml_dsa(oqs=oqs, msg=msg, priv=ml_dsa_priv, oqs_alg=ml_dsa_alg)
    sig_fa = sign_falcon(oqs=oqs, msg=msg, priv=falcon_priv, oqs_alg=falcon_alg)
    return sig_ml, sig_fa


def verify_hybrid_strict_and(
    *,
    oqs: Any,
    msg: bytes,
    sig_ml: bytes,
    sig_fa: bytes,
    ml_dsa_pub: bytes,
    falcon_pub: bytes,
    ml_dsa_alg: str,
    falcon_alg: str,
) -> bool:
    return bool(
        verify_ml_dsa(oqs=oqs, msg=msg, sig=sig_ml, pub=ml_dsa_pub, oqs_alg=ml_dsa_alg)
        and verify_falcon(oqs=oqs, msg=msg, sig=sig_fa, pub=falcon_pub, oqs_alg=falcon_alg)
    )
