<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# DigiByte Q-ID Contracts Index

This directory contains **normative, contract-locked specifications** for DigiByte Q-ID.

If **code**, tests, examples, or non-contract documentation conflict with any document
in this directory, **the contract wins**.

---

## Purpose of This Directory

The documents in `docs/CONTRACTS/` define the **stable, security-critical interface**
of DigiByte Q-ID.

They are written to:
- support **independent re-implementation**
- enable **security review**
- prevent accidental or silent breaking changes

This directory represents the **contract boundary** of the system.

---

## How to Use These Contracts

- Implementations **MUST** follow these documents exactly.
- Parsing, canonicalization, and verification rules are **fail-closed by default**.
- Any change affecting serialized formats or verification logic must be treated as
  **consensus-like**.

---

## Contract Versioning Rules

- Contract filenames end with `_vN.md`
- Any **breaking change** requires a new version (e.g. `_v2.md`)
- Older versions remain valid references for:
  - compatibility testing
  - migration tooling
  - historical audit

---

## Active Contracts

### Crypto Envelope v1
- File: `crypto_envelope_v1.md`
- Purpose: Defines the **signature envelope format** used across DigiByte Q-ID.

### Hybrid Key Container v1
- File: `hybrid_key_container_v1.md`
- Purpose: Defines the **container format** for hybrid key material (e.g. ML-DSA + Falcon).

### Login Payloads v1
- File: `login_payloads_v1.md`
- Purpose: Defines **login request/response payloads** and validation rules.

### Registration Payload v1
- File: `registration_payload_v1.md`
- Purpose: Defines **registration payloads** and validation rules.

### QID URI Scheme v1
- File: `qid_uri_scheme_v1.md`
- Purpose: Defines the canonical `qid://` URI format and parsing rules.

---

## Deprecation Notice

If `protocol_messages_v1.md` exists, treat it as **informative only** and prefer:
- `login_payloads_v1.md`
- `registration_payload_v1.md`

---

**Author:** DarekDGB  
**License:** MIT (2025)
