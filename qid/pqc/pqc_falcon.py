from __future__ import annotations

from typing import Any


def sign_falcon(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    alg = oqs_alg or "Falcon-512"

    signer = None  # IMPORTANT: del on error to avoid pytest repr segfaults
    try:
        with oqs.Signature(alg) as signer:
            if hasattr(signer, "import_secret_key"):
                signer.import_secret_key(priv)  # type: ignore[attr-defined]
                return signer.sign(msg)

            try:
                return signer.sign(msg, priv)
            except TypeError:
                return signer.sign(msg)

    except Exception:
        try:
            del signer
        except Exception:
            pass
        raise RuntimeError("pqc_falcon signing failed") from None


def verify_falcon(
    *,
    oqs: Any,
    msg: bytes,
    sig: bytes,
    pub: bytes,
    oqs_alg: str | None = None,
) -> bool:
    alg = oqs_alg or "Falcon-512"

    verifier = None  # IMPORTANT: del on error to avoid pytest repr segfaults
    try:
        with oqs.Signature(alg) as verifier:
            if hasattr(verifier, "import_public_key"):
                verifier.import_public_key(pub)  # type: ignore[attr-defined]
                return bool(verifier.verify(msg, sig))

            try:
                return bool(verifier.verify(msg, sig, pub))
            except TypeError:
                return bool(verifier.verify(msg, sig))

    except Exception:
        try:
            del verifier
        except Exception:
            pass
        return False
