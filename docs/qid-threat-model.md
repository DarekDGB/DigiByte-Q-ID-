# DigiByte Q‑ID — Threat Model (Full Specification)

Status: **v1 – Complete Draft**

---

## 1. Assets to Protect

Q‑ID protects a minimal but highly sensitive set of authentication and identity assets:

### **1.1 Identity Keys**
- User long‑term post‑quantum keypair (PQC).
- Optional transitional classical keypair.
- Service’s identity public key.

### **1.2 Device Bindings**
- Secure binding between a wallet installation and a Q‑ID identity.
- Biometric or secure enclave–based unlock paths.

### **1.3 Authentication Sessions**
- Login requests.
- Registration requests.
- Nonces and session identifiers.

### **1.4 Service Bindings**
- Relationship between a service (domain) and user identity.
- Callback URLs tied to those relationships.

### **1.5 Integrity of Communication**
- QR payloads.
- Encoded URIs.
- Wallet → service response payloads.

---

## 2. Adversaries

### **2.1 Network Attacker (MITM)**
Capabilities:
- Observe, intercept, or modify traffic.
- Replace callback URLs.
- Replay login payloads.

### **2.2 QR Payload Manipulator**
Capabilities:
- Replace QR codes displayed on a webpage.
- Embed malicious domains or altered nonce values.

### **2.3 Device Compromise**
Capabilities:
- Malware reading keys if device storage is broken.
- Keylogging or screen recording attacks.

### **2.4 Fake Services (Phishing)**
Capabilities:
- Clone a legitimate website.
- Use legitimate-looking QR codes to steal login attempts.

### **2.5 Fake Wallet Applications**
Capabilities:
- Pretend to be a real Q‑ID wallet.
- Trick users into approving malicious actions.

### **2.6 Replay Attackers**
Capabilities:
- Capture a legitimate login QR.
- Reuse it against the service later.

### **2.7 Quantum Adversary (Future)**
Capabilities:
- Break classical ECDSA/Schnorr.
- Break non‑PQC encryption operations.
- Attempt large-scale identity correlation.

---

## 3. Attack Surfaces

### **3.1 QR Payload Encoding/Decoding**
- Modification of JSON components.
- Removal or replacement of key fields.
- Injection of malicious callback URLs.

### **3.2 Callback URLs**
- Domain mismatches.
- Downgrade from HTTPS to HTTP.
- Open redirect exploits.

### **3.3 Wallet-Side Display**
- Incorrect or missing domain verification.
- Poor UX that hides critical security information.

### **3.4 Service Endpoints**
- Failure to validate signatures.
- Failure to validate nonce freshness.
- Acceptance of malformed payloads.

### **3.5 Randomness / Nonce Generation**
- Predictable nonces may enable session hijacking.

### **3.6 Device OS Compromise**
- Jailbroken or rooted devices.
- Weak biometric fallback paths.

### **3.7 Out-of-Band Phishing**
- Attackers sending QR codes via email/message.
- Social engineering.

---

## 4. Threats & Mitigations

### **4.1 QR Code Tampering**
**Threat:** Attacker replaces displayed QR with malicious one.  
**Mitigations:**
- Wallet displays **service_id** prominently.
- Service signs the login/registration payload (future).
- Hash commitments to payload contents.

---

### **4.2 Replay Attacks**
**Threat:** Captured Q‑ID login request reused later.  
**Mitigations:**
- Strict nonce freshness enforcement.
- Service stores used nonces temporarily.
- Wallet may include timestamp/expiry.

---

### **4.3 MITM Modification of Callback URL**
**Threat:** Attacker intercepts Q‑ID response and sends altered callback.  
**Mitigations:**
- Wallet enforces HTTPS only.
- Wallet compares domain shown in QR to callback target.
- Payload signing (future).

---

### **4.4 Fake Service / Phishing**
**Threat:** User scans QR for a fake website.  
**Mitigations:**
- Wallet displays:
  - Domain
  - Requested action
  - Risk warning if mismatched
- Service identity keys pinned in wallet (future).

---

### **4.5 Fake Wallet Apps**
**Threat:** Malicious app signs on behalf of user.  
**Mitigations:**
- Open-source reference wallet.
- Verified builds.
- OS-level app signing.
- Biometric confirmation for every login.

---

### **4.6 Compromised Device**
**Threat:** Malware steals keys.  
**Mitigations:**
- Use secure enclave / hardware-backed key storage.
- PQC key types resistant to extraction.
- Enforce biometrics on sensitive actions.

---

### **4.7 Quantum Attacks**
**Threat:** Future PQ computers break classical cryptography.  
**Mitigations:**
- PQC-first design (Dilithium or equivalent).
- Hybrid classical+PQC signatures (optional).
- Future‑proofing by modular crypto layer in codebase.

---

## 5. Trust Assumptions

### **5.1 The Wallet**
- Stores private keys securely.
- Displays correct service identity.
- Validates payload structure strictly.

### **5.2 The Service**
- Verifies signatures.
- Enforces nonce uniqueness.
- Implements strong TLS.
- Protects stored identity bindings.

### **5.3 The User**
- Confirms the domain before approving login.
- Uses non‑compromised device.
- Does not approve suspicious prompts.

---

## 6. Residual Risks

### **6.1 Social Engineering**
No system can fully protect against skilled manipulation.

### **6.2 Compromised Operating System**
Rooted/jailbroken devices remain high-risk.

### **6.3 QR Scanning in Hostile Environments**
Attackers could place altered QR codes over real ones.

### **6.4 Slow Adoption of PQC Standards**
Mixed environments may delay full PQ security.

### **6.5 Side-Channel Attacks on Mobile Hardware**
Out of scope but a theoretical long-term risk.

---

## 7. Summary

Q‑ID significantly raises security guarantees above classical Digi‑ID by adding:

- PQC identity foundations  
- Strong nonce‑based anti‑replay  
- Clear wallet-side domain verification  
- Clean separation of service vs. wallet roles  
- Extensible protocol for future signing and binding

This threat model will evolve as the protocol grows, especially once PQ signature integration and multi-device identity binding are implemented.

