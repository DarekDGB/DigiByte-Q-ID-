<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# 🔐 DigiByte Q-ID
## Quantum-Ready Authentication Protocol with Signed Payloads & Optional PQC Backends
### Developer Preview v0.1 (Contract-Locked)

> **DigiByte Q-ID is a standalone authentication protocol designed as a secure evolutionary successor to Digi-ID.**
> It operates independently and provides integration helpers for Adamantine Wallet–style systems.

---

## 1. What Q-ID Is (and Is Not)

**Q-ID is a cryptographically signed authentication protocol.**

It provides:
- deterministic payload signing
- strict verification rules
- replay protection via nonces
- optional post-quantum cryptography (PQC)
- hybrid (dual-algorithm) signatures
- fail-closed security semantics

**Q-ID is NOT:**
- a wallet
- a key custody solution
- a UX framework
- an automatic PQC switcher
- a background network service

Wallets and services explicitly choose how to integrate it.

---

## 2. Core Design Principles

Q-ID is built around the following **non-negotiable guarantees**:

- **Fail-closed** — any malformed input fails verification
- **Deterministic** — canonical JSON, stable hashing
- **No silent fallback** — PQC never degrades silently
- **CI-safe by default** — no external crypto deps required
- **Explicit opt-in for real PQC**
- **Hybrid = strict AND**, never OR
- **Test-locked contracts** (≥ 95% coverage enforced)

---

## 3. High-Level Flow

```
Service → QR Login Request → Wallet
Wallet → Signed Login Response → Service
Service → Verify → Accept or Reject
```

---

## 4. Repository Structure

```
qid/
├─ crypto.py
├─ protocol.py
├─ binding.py
├─ pqc_backends.py
├─ pqc_sign.py
├─ pqc_verify.py
├─ hybrid_key_container.py
├─ integration/
│  └─ adamantine.py
└─ uri_scheme.py
```

---

## 5. Cryptographic Algorithms

| Identifier | Purpose | Default Mode |
|----------|--------|--------------|
| `dev-hmac-sha256` | CI / development | Stub |
| `pqc-ml-dsa` | ML-DSA (Dilithium family) | Stub → real via liboqs |
| `pqc-falcon` | Falcon family | Stub → real via liboqs |
| `pqc-hybrid-ml-dsa-falcon` | Hybrid (ML-DSA + Falcon) | Stub → real via container |

Legacy alias:
- `hybrid-dev-ml-dsa` (compatibility only)

---

## 6. Stub Mode vs Real PQC Mode

### Default (CI-Safe Stub Mode)

- No PQC dependencies required
- Deterministic testable signatures
- Used in CI and local development

### Real PQC Mode (Explicit Opt-In)

```bash
export QID_PQC_BACKEND=liboqs
export QID_PQC_TESTS=1
```

---

## 7. Hybrid Signatures

Hybrid signatures require **both** ML-DSA and Falcon to verify.
Any failure ⇒ authentication fails.

---

## 8. Protocol Layer

Supports:
- login requests
- login responses
- registration payloads

---

## 9. Dual-Proof Mode

When `require="dual-proof"`:
1. legacy signature verified
2. binding verified
3. PQC signature(s) verified

Fail-closed by design.

---

## 10. Adamantine Integration

Module:
```
qid.integration.adamantine
```

Helpers only. No key custody.

---

## 11. QR & URI Handling

```
qid://login?d=<base64url(json)>
```

---

## 12. Test Suite & CI

- ≥90% coverage enforced
- CI-safe default
- Real PQC tests opt-in

---

## 13. Threat Model

Partially inline. Dedicated document planned.

---

## 14. Future Work

- Guardian / Shield telemetry
- Extended threat modeling

Non-binding.

---

## 15. Contributing

Security-critical project.
Fail-closed, deterministic, tested.

---

## 16. Summary

✔ Signed authentication  
✔ Optional PQC backend  
✔ Hybrid enforcement  
✔ Fail-closed verification  
✔ CI-safe default  
✔ 90% coverage enforced  

---

**MIT License — DarekDGB**  
_Q-ID does not guess. It verifies._
