from qid.models import (
    IdentityType,
    KeyKind,
    QIDKey,
    QIDIdentity,
    QIDDevice,
    QIDCredential,
    QIDAttestation,
)


def test_enums_are_strings() -> None:
    assert IdentityType.USER.value == "user"
    assert KeyKind.PQC.value == "pqc"


def test_models_defaults_are_independent() -> None:
    k1 = QIDKey(
        key_id="k1",
        kind=KeyKind.CLASSICAL,
        algorithm="secp256k1",
        public_key="pub1",
        created_at="2026-01-01",
    )
    k2 = QIDKey(
        key_id="k2",
        kind=KeyKind.PQC,
        algorithm="ml-dsa",
        public_key="pub2",
        created_at="2026-01-01",
    )

    a = QIDIdentity(identity_id="id-a", identity_type=IdentityType.USER)
    b = QIDIdentity(identity_id="id-b", identity_type=IdentityType.USER)

    a.keys.append(k1)
    b.keys.append(k2)

    assert [k.key_id for k in a.keys] == ["k1"]
    assert [k.key_id for k in b.keys] == ["k2"]

    # default_factory: metadata dicts must not be shared
    a.metadata["x"] = 1
    assert "x" not in b.metadata


def test_device_credential_attestation_minimal() -> None:
    dev = QIDDevice(device_id="d1", label="My iPhone", platform="iOS")
    assert dev.device_id == "d1"
    assert dev.metadata == {}

    cred = QIDCredential(
        credential_id="c1",
        identity_id="id-a",
        service_id="example.com",
        level=2,
    )
    assert cred.level == 2
    assert cred.is_revoked is False

    att = QIDAttestation(
        attestation_id="a1",
        issuer_identity_id="issuer",
        subject_identity_id="subject",
        statement="KYC level 2",
        created_at="2026-01-01",
    )
    assert att.signature is None
    assert att.metadata == {}
