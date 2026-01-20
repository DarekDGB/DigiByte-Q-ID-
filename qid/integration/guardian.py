"""
MIT License
Copyright (c) 2025 DarekDGB

Guardian rules integration helpers for Q-ID.

This module is intentionally *fail-closed* until a contract-locked Guardian
integration spec exists.

Rationale:
- Prevents accidental reliance on stub behavior.
- Keeps the namespace stable for future integration work.
- Forces explicit implementation before use in production.

If you need Guardian integration, implement it behind a normative contract
under docs/CONTRACTS and add deterministic tests.
"""

from __future__ import annotations


class GuardianIntegrationNotImplemented(RuntimeError):
    """Raised when Guardian integration is invoked before it is implemented."""


def require_guardian_integration() -> None:
    """
    Fail-closed sentinel.

    Any caller attempting to use Guardian integration must implement the real
    logic first (contract + tests). This prevents silent stub usage.
    """
    raise GuardianIntegrationNotImplemented(
        "Guardian integration for Q-ID is not implemented. "
        "Add a contract-locked spec and deterministic tests before enabling."
    )
