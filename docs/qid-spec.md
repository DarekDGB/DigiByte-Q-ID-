# DigiByte Q-ID — Technical Specification (Skeleton v0.1)

Status: **skeleton – login + registration defined**

This document describes the first version of the Q-ID payload formats
and URI schemes implemented in the reference Python package.

---

## 1. Overview

Q-ID is a passwordless, decentralized identity layer for DigiByte.

Actors:

- **User** – person controlling a DigiByte wallet.
- **Wallet** – Q-ID capable wallet (e.g. Adamantine) that can scan /
  display Q-ID QR codes and sign responses.
- **Service** – website / app that wants to authenticate a user.
- **Verifier** – backend component that verifies Q-ID responses.

Main flows (current scope):

1. **Registration** – bind a DigiByte address + public key to a service.
2. **Login** – authenticate using an existing Q-ID registration.

Recovery, revocation, multi-device and PQC details will be added later.

---

## 2. Data Structures (v0.1)

### 2.1 Login Request Payload

```jsonc
{
  "type": "login_request",
  "service_id": "example.com",
  "nonce": "random-unique-string",
  "callback_url": "https://example.com/qid/callback",
  "version": "1"
}
```

### 2.2 Registration Request Payload

```jsonc
{
  "type": "registration",
  "service_id": "example.com",
  "address": "dgb1qxyz123example",
  "pubkey": "EXAMPLEPUBKEY",
  "nonce": "abcdef123456",
  "callback_url": "https://example.com/qid/register",
  "version": "1"
}
```

---

## 3. URI Formats

### 3.1 Login Request URI

```
qid://login?d=<base64url(JSON)>
```

### 3.2 Registration Request URI

```
qid://register?d=<base64url(JSON)>
```

---

## 4. Cryptography (Placeholder)

Future versions will include:

- Classical signatures (Ed25519 / secp256k1)
- PQC signatures via containers
- Hybrid verification flows

---

## 5. Security Considerations (Draft)

- All callbacks must use HTTPS
- Nonces prevent replay attacks
- Avoid personal data in payloads
- PQC upgrade path planned

