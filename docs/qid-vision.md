# DigiByte Q-ID — Vision

Status: **draft – v0.1**

---

## 1. Why Q-ID?

Digi-ID showed how powerful it is to login with a **wallet instead of a password**.
Users scan a QR code, sign a message, and they are in. No usernames, no passwords,
no password leaks.

But the world is moving toward:

- **quantum-capable attackers**
- multi-device wallets
- richer security policies (Guardian / Adamantine / Shield)
- deeper integration between identity and on-chain signals

Q-ID is the evolution step: **Digi-ID reborn for a quantum-aware future.**

---

## 2. Core Idea

Q-ID is a **passwordless, decentralized identity layer for DigiByte** that:

- Keeps the *simplicity* of Digi-ID (scan → approve → logged in).
- Upgrades the **crypto** so it can survive a quantum future.
- Connects identity and login to the **defensive architecture** you have built:
  Adamantine Wallet, Guardian rules, and the DigiByte Quantum Shield.

At the protocol level, Q-ID is just:

1. Small JSON payloads (`login_request`, `registration`).
2. Wrapped in a `qid://` URI.
3. Carried by QR codes, deeplinks, or copy–paste.
4. Verified by services using a simple API.

Everything else (policies, PQC, risk engine, Shield integration) can grow on top.

---

## 3. Goals

Q-ID is designed to be:

### 3.1 Simple for Users

- No passwords.
- No secret phrases typed into websites.
- Clear "Approve login for *example.com*?" style UX in the wallet.

### 3.2 Easy for Services

- Integration through **simple HTTP/JSON APIs**.
- Clear JSON schemas for requests and responses.
- No need to run a DigiByte node in the first version (but possible later).

### 3.3 Quantum-Aware

- Keys and payloads designed so that **PQC or hybrid keys** can be introduced
  without breaking the basic flow.
- Identities can hold multiple keys (classical + PQC).
- Services can express minimum requirements through policy levels later on.

### 3.4 Deeply Connected to DigiByte

- Identities can be anchored to DigiByte addresses and transactions.
- Q-ID can use tiny on-chain anchors (UTXO / DigiAsset markers) to signal
  higher-assurance identities.
- Future Guardian/Shield rules can consume Q-ID trust levels for protection.

### 3.5 Open and MIT-Licensed

- Reference implementation is **MIT-licensed**.
- Designed to be copied, improved, and extended by the DigiByte community.
- No closed or proprietary pieces in the core protocol.

---

## 4. How Q-ID Relates to Existing Components

### 4.1 Adamantine Wallet

Adamantine can become the **first Q-ID capable wallet**:

- It knows how to parse `qid://` URIs.
- It can show human-readable confirmations to the user.
- It can sign login/registration responses with classical and PQC keys.
- It can use Guardian/Shield signals to block risky logins.

Q-ID is the **identity & login face** of Adamantine.

### 4.2 Guardian & Policies

Guardian can consume Q-ID information such as:

- which identity is trying to perform an action
- from which device
- with which assurance level
- how old the login session is

Example policies:

- "High value transactions require recent Q-ID login with level ≥ 2"
- "Block any action from untrusted devices"
- "Allow low-value operations with basic Q-ID, require stronger Q-ID for more"

### 4.3 DigiByte Quantum Shield

Shield watches the **network**. Q-ID watches **who** is doing what.

Together they create a two-sided defense:

- Shield = "Is the network behaving correctly?"
- Q-ID   = "Is this user / device / session trustworthy?"

---

## 5. Roadmap (Conceptual)

This repository currently implements:

- Login request payload + URI (qid://login?d=…)
- Registration request payload + URI (qid://register?d=…)
- Roundtrip tests for both flows
- A documented mini-spec for payloads and URIs

Future steps (high level):

1. **Wallet responses**
   - Define how the wallet returns signed login/registration responses.
   - Include identity IDs, key IDs, and signatures.

2. **Service-side verification API**
   - Expand `qid-api-server.md` with concrete request/response JSON.
   - Provide a minimal Python reference verifier.

3. **Identity storage & credentials**
   - Map Q-ID registrations to persistent credentials.
   - Connect them to `QIDIdentity`, `QIDKey`, `QIDCredential` models.

4. **PQC / Hybrid keys**
   - Integrate with PQC containers.
   - Add explicit algorithm + key-type metadata.

5. **Guardian & Shield integration**
   - Expose Q-ID trust signals to Guardian.
   - Use Shield insights (reorgs, anomalies) to influence Q-ID policy.

---

## 6. Philosophy

Q-ID is built on three principles:

1. **User sovereignty**  
   The user controls their identity through their wallet. Services can
   verify identities, but they never own them.

2. **Defense in depth**  
   No single component is "the security". Wallet, node, Shield, Guardian,
   and Q-ID all work together.

3. **Transparency & humility**  
   Everything is open, readable, and versioned. The protocol starts small,
   grows carefully, and always prefers clarity over complexity.

Q-ID is not trying to be everything at once.
It is a **small, sharp tool** that can grow with DigiByte, quantum threats,
and the community that protects them.
