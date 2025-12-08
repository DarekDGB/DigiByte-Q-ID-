"""
High-level DigiByte Q-ID protocol flows.

Later this module will implement:
- register_identity()  -> first-time binding between wallet and service
- login()              -> passwordless authentication
- revoke_credential()
- rotate_keys()
- recover_identity()

Right now it only returns placeholder responses.
"""

from typing import Any, Dict


def register_identity(request: Dict[str, Any]) -> Dict[str, Any]:
    """Placeholder registration flow."""
    return {"status": "todo", "detail": "Q-ID registration not implemented yet."}


def login(request: Dict[str, Any]) -> Dict[str, Any]:
    """Placeholder login flow."""
    return {"status": "todo", "detail": "Q-ID login not implemented yet."}
