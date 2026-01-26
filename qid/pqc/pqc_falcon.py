"""
Falcon signing + verification via python-oqs.

Contract:
- Deterministic behavior (no silent downgrade).
- Any API mismatch should raise PQCBackendError (handled upstream).
- verify must fail-closed (return False) on internal errors.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from qid.pqc_backends import PQCBackendError


def _free_if_possible(obj: Any) -> None:
    free = getattr(obj, "free", None)
    if callable(free):
        try:
            free()
        except Exception:
            pass


def _make_signature_ctx(oqs: Any, oqs_alg: str, *, secret_key: Optional[bytes]) -> Any:
    Sig = getattr(oqs, "Signature", None)
    if Sig is None or not callable(Sig):
        raise PQCBackendError("Invalid oqs backend object: missing callable Signature")

    last_err: Optional[BaseException] = None

    if secret_key is not None:
        for ctor in (
            lambda: Sig(oqs_alg, secret_key=secret_key),
            lambda: Sig(oqs_alg, secret_key),
        ):
            try:
                return ctor()
            except TypeError as e:
                last_err = e
            except Exception as e:
                last_err = e

    try:
        ctx = Sig(oqs_alg)
    except Exception as e:
        raise PQCBackendError("liboqs Signature ctor failed") from e

    if secret_key is not None:
        imp = getattr(ctx, "import_secret_key", None)
        if callable(imp):
            try:
                imp(secret_key)
                return ctx
            except Exception as e:
                _free_if_possible(ctx)
                raise PQCBackendError("liboqs import_secret_key failed") from e

        if hasattr(ctx, "secret_key"):
            try:
                setattr(ctx, "secret_key", secret_key)
                return ctx
            except Exception as e:
                _free_if_possible(ctx)
                raise PQCBackendError("liboqs setting secret_key failed") from e

        _free_if_possible(ctx)
        raise PQCBackendError(
            "liboqs backend does not support supplying a secret key (no ctor form, no import_secret_key)."
        ) from last_err

    return ctx


def _call_sign(ctx: Any, msg: bytes, priv: bytes) -> bytes:
    sign_fn: Optional[Callable[..., Any]] = getattr(ctx, "sign", None)
    if not callable(sign_fn):
        raise PQCBackendError("liboqs Signature object missing sign()")

    try:
        out = sign_fn(msg)
        if not isinstance(out, (bytes, bytearray)):
            raise PQCBackendError("liboqs sign() returned non-bytes")
        return bytes(out)
    except TypeError:
        try:
            out = sign_fn(msg, priv)
            if not isinstance(out, (bytes, bytearray)):
                raise PQCBackendError("liboqs sign() returned non-bytes")
            return bytes(out)
        except TypeError as e:
            raise PQCBackendError("liboqs signing failed (Signature API mismatch)") from e
    except Exception as e:
        raise PQCBackendError("liboqs signing failed") from e


def _call_verify(ctx: Any, msg: bytes, sig: bytes, pub: bytes) -> bool:
    verify_fn: Optional[Callable[..., Any]] = getattr(ctx, "verify", None)
    if not callable(verify_fn):
        raise PQCBackendError("liboqs Signature object missing verify()")

    try:
        return bool(verify_fn(msg, sig, pub))
    except TypeError:
        try:
            return bool(verify_fn(sig, msg, pub))
        except Exception:
            return False
    except Exception:
        return False


def sign_falcon(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str) -> bytes:
    ctx = _make_signature_ctx(oqs, oqs_alg, secret_key=priv)
    try:
        return _call_sign(ctx, msg, priv)
    finally:
        _free_if_possible(ctx)


def verify_falcon(*, oqs: Any, msg: bytes, sig: bytes, pub: bytes, oqs_alg: str) -> bool:
    ctx = _make_signature_ctx(oqs, oqs_alg, secret_key=None)
    try:
        return _call_verify(ctx, msg, sig, pub)
    finally:
        _free_if_possible(ctx)
