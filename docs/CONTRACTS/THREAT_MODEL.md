<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# 🔐 DigiByte Q-ID — Threat Model
## **Authentication Protocol v0.1.x (CI-Locked)**

This document defines the **explicit threat model** for the DigiByte Q-ID protocol.
It enumerates **assumed adversaries**, **protected assets**, **attack surfaces**, and **enforced mitigations**.

Q-ID is designed as **fail-closed**, **contract-driven**, and **cryptographically explicit**.
Anything not explicitly allowed is considered forbidden.

---

## 1. Security Goals (What Q-ID Protects)

Q-ID protects the following assets:

- **User authentication intent**
- **Service identity binding**
- **Wallet identity binding**
- **Nonce freshness**
- **Algorithm integrity (no downgrade)**
- **Signature authenticity**
- **Replay resistance**
- **Forward migration to PQC**

Out of scope by design:
- Wallet key custody
- UI/UX safety
- Malware on user devices
- Social engineering
- Transport-layer security (TLS assumed)

---

## 2. Adversary Model

Q-ID assumes the following adversaries exist:

### A1. Network Attacker
- Can observe, replay, delay, and reorder traffic
- Cannot break modern cryptography

### A2. Malicious Service
- Attempts to reuse or tamper with authentication payloads
- Attempts callback or service spoofing

### A3. Malicious Wallet
- Attempts to forge or downgrade authentication responses

### A4. Downgrade Attacker
- Attempts to force weaker algorithms or legacy modes

### A5. Future Quantum Adversary
- Can break classical ECDSA / Schnorr
- Cannot break NIST PQC algorithms (assumption)

---

## 3. Trust Assumptions

Q-ID explicitly assumes:

- Cryptographic primitives behave as specified
- Hash functions are collision-resistant
- PQC algorithms are correctly implemented in liboqs
- Wallets protect their own private keys
- Services validate responses correctly

Q-ID **does not** assume:
- Honest services
- Honest wallets
- Trusted networks

---

## 4. Attack Surfaces & Mitigations

### 4.1 Replay Attacks

**Threat:**
- Reuse of a valid authentication response

**Mitigations:**
- Mandatory nonce
- Strict nonce equality checks
- Service-side nonce lifecycle enforcement
- Canonical payload encoding

**Result:** Replay fails deterministically

---

### 4.2 Service / Callback Spoofing

**Threat:**
- Authentication response reused across services

**Mitigations:**
- `service_id` is signed
- `callback_url` is signed
- Server enforces strict equality

**Result:** Cross-service replay impossible

---

### 4.3 Signature Forgery

**Threat:**
- Attacker forges a valid response

**Mitigations:**
- Cryptographic signature verification
- Explicit algorithm identifiers
- Public-key verification

**Result:** Forgery infeasible

---

### 4.4 Algorithm Downgrade

**Threat:**
- Forcing weaker crypto (e.g. DEV instead of PQC)

**Mitigations:**
- Algorithm is signed inside payload
- Backend enforcement (`enforce_no_silent_fallback`)
- Explicit algorithm allowlists
- No implicit defaults

**Result:** Downgrade attempts fail closed

---

### 4.5 Hybrid Signature Bypass

**Threat:**
- Providing only one valid signature in hybrid mode

**Mitigations:**
- Hybrid requires **both** ML-DSA and Falcon
- Explicit hybrid container validation
- Strict AND verification logic

**Result:** Partial signatures rejected

---

### 4.6 Backend Substitution

**Threat:**
- Running PQC logic without real PQC backend

**Mitigations:**
- `QID_PQC_BACKEND=liboqs` required
- Runtime enforcement at sign/verify time
- No silent fallback to stubs

**Result:** Real PQC required when declared

---

### 4.7 Payload Tampering

**Threat:**
- Modifying signed fields after signing

**Mitigations:**
- Canonical JSON encoding
- Full payload coverage by signature

**Result:** Any modification invalidates signature

---

## 5. Canonical Encoding Guarantees

All signed payloads use:

- Sorted keys
- No whitespace
- UTF-8 encoding
- Deterministic serialization

This prevents:
- Ambiguity attacks
- Signature confusion
- Cross-implementation inconsistencies

---

## 6. Fail-Closed Philosophy

Q-ID follows a **fail-closed** design:

- Unknown algorithms → reject
- Missing fields → reject
- Invalid envelopes → reject
- Backend mismatch → reject
- Hybrid partials → reject

There are **no silent fallbacks**.

---

## 7. Cryptographic Agility & PQC Migration

Q-ID is explicitly designed for:

- Algorithm agility
- Hybrid transition periods
- PQC-first future enforcement

Algorithm identifiers are:
- Explicit
- Signed
- Non-negotiable at verification time

---

## 8. Non-Goals (Explicitly Not Solved)

Q-ID does NOT attempt to solve:

- Wallet malware
- User deception
- UI spoofing
- Transport-layer attacks
- Key recovery

These are delegated to wallets, OS security, and TLS.

---

## 9. Summary

✔ Replay-resistant  
✔ Service-bound  
✔ Algorithm-explicit  
✔ Downgrade-resistant  
✔ PQC-ready  
✔ Hybrid-safe  
✔ Fail-closed  

Q-ID is designed to survive **hostile networks**, **malicious services**, and **future cryptographic shifts**.

---

**MIT Licensed — DarekDGB**  
Security is not a feature. It is the architecture.
