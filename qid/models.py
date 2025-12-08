"""
Core data models for DigiByte Q-ID.

These describe the core identity objects used by Q-ID:
- identities (user, service, device, wallet)
- cryptographic keys (classical, PQC, hybrid)
- service credentials (bindings)
- attestations (signed statements)

This is the foundation layer. Logic will be added later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class IdentityType(str, Enum):
    USER = "user"
    SERVICE = "service"
    DEVICE = "device"
    WALLET = "wallet"


class KeyKind(str, Enum):
    CLASSICAL = "classical"
    PQC = "pqc"
    HYBRID = "hybrid"


@dataclass
class QIDKey:
    """
    Represents a public key used by Q-ID.

    `algorithm` examples:
    - "secp256k1"
    - "ed25519"
    - "dilithium3"
    """
    key_id: str
    kind: KeyKind
    algorithm: str
    public_key: str  # encoded string

    created_at: str
    expires_at: Optional[str] = None
    is_active: bool = True

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class QIDIdentity:
    """
    Represents a Q-ID identity: user, service, device, or wallet.
    Contains keys and optional metadata.
    """
    identity_id: str
    identity_type: IdentityType

    display_name: Optional[str] = None
    keys: List[QIDKey] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class QIDDevice:
    """
    Represents a device bound to an identity.
    Example platforms: 'iOS', 'Android', 'Desktop'.
    """
    device_id: str
    label: str
    platform: Optional[str] = None
    last_seen_at: Optional[str] = None

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class QIDCredential:
    """
    Represents a binding between an identity and a service.
    Replaces username/password for login.
    """
    credential_id: str
    identity_id: str
    service_id: str

    level: int = 1
    device_id: Optional[str] = None

    created_at: str = ""
    revoked_at: Optional[str] = None
    is_revoked: bool = False

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class QIDAttestation:
    """
    Signed statement about an identity or device.
    """
    attestation_id: str

    issuer_identity_id: str
    subject_identity_id: str

    statement: str
    created_at: str

    signature: Optional[str] = None

    metadata: Dict[str, Any] = field(default_factory=dict)
