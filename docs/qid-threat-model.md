# DigiByte Q-ID — Threat Model

Status: **draft – v0.2 (signed flows + PQC-ready)**

This document captures the *current* threat model for DigiByte Q-ID as
implemented in this repo. It will evolve as we add PQC backends and
deeper Guardian / Shield integration.

---

## 1. Assets to Protect

1. **Authentication sessions**
   - Fresh Q-ID login attempts in progress.
   - Established application sessions created from successful logins.

2. **Identity material**
   - Long-term Q-ID keypairs (wallet-side).
   - Service-side verification keys / secrets.
   - Binding between a Q-ID identity and an application account.

3. **Device bindings**
   - Association of a Q-ID identity with a specific wallet device.

4. **Service bindings**
   - Mapping of `(service_id, callback_url)` to a relying party.
   - Records of which addresses / keys have logged into which service.

5. **Audit & telemetry**
   - Logs of successful / failed Q-ID logins.
   - Signals that may flow into Guardian / Shield for anomaly detection.

---

## 2. Adversaries

1. **Network attacker**
   - Can observe, modify, delay, or replay traffic between:
     - browser ↔ service
     - wallet ↔ service
   - Cannot break standard TLS if correctly configured.

2. **Malicious service**
   - A service that attempts to trick a wallet into:
     - signing for the wrong `service_id`,
     - leaking keys or sensitive data.

3. **Malicious wallet / app**
   - A compromised / fake wallet that produces bogus Q-ID responses.

4. **Compromised endpoint**
   - User device with malware.
   - Service backend with partial compromise.

5. **Replay attacker**
   - Tries to reuse previously captured Q-ID login responses.

6. **Future quantum attacker**
   - Can eventually break classical public-key schemes.
   - Motivates migration to ML-DSA / Falcon / hybrid backends.

---

## 3. Trust Assumptions

- Services correctly configure **TLS** on `callback_url`.
- Wallets store private keys in secure storage (OS keystore, hardware,
  etc.).
- Nonces are generated with sufficient entropy and are not reused.
- The dev HMAC backend is used **only** for development / testing, not
  for production deployments.
- PQC / hybrid backends will be deployed with appropriate key management
  and rotation policies.

---

## 4. Attack Scenarios & Mitigations

### 4.1. Login request tampering

**Goal:** Attacker changes the Q-ID login request (service_id, callback).

- Example: Changing `service_id` from `example.com` to `evil.com`.

**Mitigations:**

- Wallet uses `parse_login_request_uri(...)` and:
  - checks `service_id` and `callback_url` against the **expected
    service** (`QIDServiceConfig`).
- Helpers such as `prepare_signed_login_response(...)` enforce these
  checks before signing.

**Residual risk:** If a wallet integrates Q-ID without performing these
checks, it may be tricked into signing for an unexpected service. The
reference implementation *must* be reused or mirrored carefully.

---

### 4.2. Response tampering

**Goal:** Attacker modifies the Q-ID login response payload on the wire.

**Mitigations:**

- Every login response is **signed**:
  - wallet uses `sign_payload(...)` over `response_payload`.
  - server uses `verify_signed_login_response_server(...)` to validate.
- Any modification to:
  - `nonce`,
  - `service_id`,
  - `callback_url`,
  - `address`,
  - `pubkey`,
  - `key_id`,
  will cause signature verification to fail.

**Residual risk:** If a service skips verification or uses the wrong
verification key, it may accept tampered responses.

---

### 4.3. Replay of old responses

**Goal:** Attacker replays an old, valid response to gain access.

**Mitigations (recommended patterns):**

- Nonces must be:
  - **unique** per login attempt,
  - stored server-side until consumed,
  - marked as *used* after first successful verification.
- Services should reject:
  - responses for unknown / expired nonces,
  - responses where the same nonce was already used.

**Residual risk:** If a service does not track nonces, replay attacks
are possible even though signatures are valid.

---

### 4.4. Phishing / lookalike services

**Goal:** Trick users into scanning a QR code belonging to a malicious
service that visually looks like a trusted one.

**Mitigations:**

- Wallets should display:
  - `service_id`,
  - `callback_url` (or a safe, human-friendly alias),
  and allow the user to **cancel** if it looks suspicious.
- Advanced wallets can:
  - maintain a **trusted service directory**,
  - warn when logging into an unknown / untrusted `service_id`.

**Residual risk:** Highly convincing phishing pages may still succeed if
users ignore warnings.

---

### 4.5. Compromised wallet device

**Goal:** Malware on the user's device steals keys or signs unwanted
logins.

**Mitigations:**

- Use OS / hardware keystores for key storage (beyond scope of this
  repo).
- Require local user interaction (biometrics / PIN) before signing.
- Guardian / Shield can ingest Q-ID login telemetry to:
  - detect unusual patterns (new IP / device / geolocation),
  - flag risky sessions.

**Residual risk:** A fully compromised device can still sign logins;
detection may be delayed.

---

### 4.6. Compromised service backend

**Goal:** Attacker controls the service's server partially or fully.

**Mitigations:**

- Q-ID ensures that *logins themselves* are cryptographically verified,
  but cannot protect:
  - local database integrity,
  - session storage,
  - business logic abuses.

**Residual risk:** If the service is fully compromised, Q-ID cannot
guarantee account safety; it only guarantees that logins came from a
wallet that had the key.

---

### 4.7. Quantum adversary (future)

**Goal:** Break classical signatures used in early Q-ID deployments.

**Mitigations:**

- Q-ID is designed to support **pluggable crypto backends** via
  `qid.crypto`:
  - current: `dev-hmac-sha256` (testing),
  - plus PQC stubs for ML-DSA, Falcon, and hybrid.
- Protocol messages can carry:
  - `key_id`,
  - backend algorithm identifiers,
  enabling gradual migration.

**Residual risk:** Deployments that never migrate away from classical
crypto are vulnerable once practical quantum attacks exist.

---

### 4.8. Algorithm downgrade / confusion

**Goal:** Trick a verifier into accepting a response signed with a weaker
algorithm than expected.

**Mitigations:**

- Algorithm identifiers are explicit (`DEV_ALGO`, `ML_DSA_ALGO`,
  `FALCON_ALGO`, `HYBRID_ALGO`).
- Backends produce signatures that are **not interchangeable**:
  - PQC stubs include an algorithm prefix in the signed blob.
  - Hybrid signatures combine two MACs in a fixed layout.
- Services should enforce a policy such as:
  - “internet-facing logins must use PQC or hybrid backends only”.

**Residual risk:** Misconfigured services that accept all algorithms
without policy checks may weaken their own security posture.

---

### 4.9. Cross-service replay / confusion

**Goal:** Reuse a response intended for `service_id = A` to log into
`service_id = B`.

**Mitigations:**

- `service_id` and `callback_url` are part of the signed payload.
- The reference verification helpers check both fields.
- Wallet-side helpers validate that scanned URIs match the expected
  service.

**Residual risk:** If a service ignores `service_id` or a wallet signs
for arbitrary URIs, cross-service confusion is possible.

---

## 5. Guardian / Shield Integration Points

Q-ID events are natural inputs to the larger **DigiByte Quantum Shield**
stack:

- **Sentinel / DQSN / ADN**:
  - correlate login events with on-chain / node telemetry.
- **Guardian / QWG / Adaptive Core**:
  - assign risk scores to identities, devices, services.
  - trigger additional checks or lockouts on suspicious activity.

Examples:

- Sudden spike in failed Q-ID logins from a single IP range.
- Logins for the same identity from impossible geolocations.
- An address involved in suspected attacks attempting to log into
  multiple services.

These integrations are not yet implemented in this repo, but the
structures (`response_payload`, `service_id`, `address`, `key_id`,
`algorithm`) are designed to feed them.

---

## 6. Open Questions & Future Work

- How should services publish and rotate their verification keys?
- How should wallets present service identity in a trusted way
  (UI / directories / DNS-based bindings)?
- What is the recommended PQC backend ordering (pure PQC vs. hybrid)?
- How do we best encode algorithm identifiers for long-term
  compatibility?
- How should Guardian / Shield fuse Q-ID telemetry with node-level
  signals for richer anomaly detection?

This threat model will be updated as we gain more feedback from
integrators and as the DigiByte ecosystem adopts Q-ID in production.
