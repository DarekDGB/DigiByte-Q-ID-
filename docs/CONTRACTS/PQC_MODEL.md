<!--
Author: DarekDGB
License: MIT (c) 2025
-->

# DigiByte Q-ID — PQC Model (Stub vs Real Backend)

**Author:** DarekDGB  
**License:** MIT (c) 2025

## Purpose

Q-ID is designed to be **post-quantum-ready** while staying **CI-safe** and **fail-closed**.

This repository intentionally supports two modes:

1. **CI-safe stub crypto** (always available)
2. **Real PQC backend** (optional, explicitly selected)

The goal is to keep the codebase buildable and testable everywhere, while still enabling real ML-DSA / Falcon / hybrid enforcement when the environment supports it.

---

## Definitions

### Algorithms
- **DEV**: `dev-hmac-sha256` (CI-safe baseline)
- **ML-DSA**: `pqc-ml-dsa`
- **Falcon**: `pqc-falcon`
- **Hybrid**: `pqc-hybrid-ml-dsa-falcon` (**strict AND**)

### Signature envelope
Q-ID uses an explicit envelope format (versioned) to avoid ambiguity and to fail closed on parsing or mismatch.

---

## Mode 1: CI-safe stub crypto (default)

### What it is
Stub crypto is deterministic, dependency-free signing/verification used to:
- keep CI green without liboqs
- prove API behavior and fail-closed logic
- validate envelope format + canonicalization rules

### What it is NOT
Stub crypto is **not** intended to be “secure cryptography”.
It is a **contract + behavior scaffold** that enforces correct program structure.

### Contract rule
- `generate_keypair()` MUST NOT require `oqs/liboqs`
- real-backend requirements are enforced at **sign/verify time**, not key generation

---

## Mode 2: Real PQC backend (optional, explicit)

### How it activates
A real backend activates only when explicitly selected by environment/config (e.g. `QID_PQC_BACKEND=liboqs`).

### Fail-closed rule (no silent fallback)
When a real backend is selected:
- ML-DSA / Falcon / Hybrid requests MUST NOT silently fall back to stub signing
- if real PQC cannot run (missing deps, invalid container, etc.), **raise or fail closed**

This prevents downgrade attacks and “works on my machine” ambiguity.

---

## Hybrid model: ML-DSA + Falcon (strict AND)

Hybrid signatures are treated as **two independent signatures**:
- one ML-DSA signature
- one Falcon signature

**Verification requires BOTH to pass.**  
There is no “either/or” path.

### Why strict AND?
- prevents downgrade inside hybrid
- gives two independent security margins
- keeps semantics unambiguous for auditors and integrators

---

## Hybrid container: what it is

Hybrid signing with a real backend requires a container that can provide:
- ML-DSA key material
- Falcon key material

The container is validated and must match `pqc-hybrid-ml-dsa-falcon`.
If it cannot be decoded/validated, Q-ID fails closed.

---

## What “done” means

You can say Q-ID is “PQC-wired” only when:

- real backend selection is supported and tested
- ML-DSA signing and verification are executed with the backend
- Falcon signing and verification are executed with the backend
- hybrid AND enforcement is executed with the backend
- no path allows silent fallback when the backend is selected

CI remains deterministic and green even without PQC dependencies.

---

## Security invariants (non-negotiable)

- Deterministic signing input (canonical JSON bytes)
- Explicit envelope versioning
- No silent fallback / downgrade
- Hybrid = strict AND
- Fail-closed on parse mismatch, algorithm mismatch, or backend errors
