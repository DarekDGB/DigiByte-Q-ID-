<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# 🔐 DigiByte Q-ID

**Quantum‑Ready Authentication Protocol** for DigiByte — designed as a long‑term successor to Digi‑ID.

Q‑ID provides **cryptographically signed login / registration flows** with a **CI‑safe stub crypto mode** by default, and an **optional real PQC backend** (`liboqs`) when available.

> **Contracts are the source of truth.**  
> Anything under `docs/CONTRACTS/` is **normative**. If code or other docs conflict, **the contract wins**.

---

## Status

- **Stage:** Developer Preview (contract-led reference implementation)
- **CI:** ✅ passing
- **Coverage:** ≥ 90% enforced (fail‑closed defaults)
- **PQC:** **optional** via `liboqs` (tests skip cleanly if not installed)

---

## What Q-ID covers

- Signed **login** requests/responses
- Signed **registration** payloads
- `qid://` URI scheme for QR-first UX
- **Algorithm selection** (DEV / PQC / HYBRID)
- **Fail‑closed** verification rules (no silent fallback)

---

## Algorithms

These algorithm identifiers are contract‑visible (see `qid/crypto.py`):

- `dev-hmac-sha256` — **CI‑safe DEV** signing for deterministic tests and examples
- `pqc-ml-dsa` — PQC algorithm ID (ML‑DSA / Dilithium family)
- `pqc-falcon` — PQC algorithm ID (Falcon family)
- `pqc-hybrid-ml-dsa-falcon` — **HYBRID**: requires both ML‑DSA and Falcon signatures

Legacy compatibility:
- `hybrid-dev-ml-dsa` is accepted as a **legacy alias** (do not use for new integrations).

---

## Stub mode vs real PQC backend

### Default: CI-safe stub mode (no environment variable)

If `QID_PQC_BACKEND` is **not** set, the repo runs in a **portable stub mode**:
- deterministic keys/signatures (suitable for CI and examples)
- **no external PQC toolchain required**

### Optional: real PQC backend (liboqs)

Set:

- `QID_PQC_BACKEND=liboqs`

In this mode:
- PQC algorithms are **enforced** (no silent fallback)
- if `liboqs` is not available, signing raises `PQCBackendError` (callers may catch and fail‑closed)

**Hybrid rule (important):**
- when `QID_PQC_BACKEND` is selected and the algorithm is `pqc-hybrid-ml-dsa-falcon`,
  signing requires an explicit `hybrid_container_b64` (Hybrid Key Container v1).  
  Missing container ⇒ signing fails (and protocol helpers are designed to fail‑closed).

---

## Quickstart

### Run tests

```bash
python -m pytest --cov=qid --cov-report=term-missing --cov-fail-under=90 -q
```

### Try examples

See `examples/` for reference scripts:
- `examples/login_roundtrip.py`
- `examples/example_server.py`

---

## Documentation map

### Normative contracts (must match code)

- `docs/CONTRACTS/INDEX.md`
- `docs/CONTRACTS/crypto_envelope_v1.md`
- `docs/CONTRACTS/qid_uri_scheme_v1.md`
- `docs/CONTRACTS/protocol_messages_v1.md`
- `docs/CONTRACTS/hybrid_key_container_v1.md`
- `docs/CONTRACTS/login_payloads_v1.md`
- `docs/CONTRACTS/registration_payload_v1.md`

### Non-normative developer docs

- `docs/qid-crypto-backends.md` — backend selection + fail-closed rules
- `docs/qid-api-server.md` — reference server notes
- `docs/qid-adamantine-integration.md` — wallet integration notes

---

## Design principles (guardrails)

- **Fail‑closed by default** (invalid / missing data ⇒ deny)
- **No silent fallback** when a PQC backend is selected
- **Deterministic behavior** in CI/stub mode
- **Contract‑first discipline** for anything consensus‑like (serialization / canonicalization / verification)

---

## License

MIT — Copyright (c) 2025 **DarekDGB**  
See `LICENSE.md`.
