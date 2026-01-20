<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# Login Payloads v1 (Normative Contract)

This contract defines the **login request** and **login response** payload formats
for DigiByte Q-ID, including required fields and fail-closed validation rules.

If code or tests conflict with this contract, **this contract wins**.

---

## 1. Canonical Serialization

All payloads MUST be treated as JSON objects and MUST be serialized to bytes using
**canonical JSON** for signing and verification:

- UTF-8
- `sort_keys = true`
- separators = `(",", ":")`
- no whitespace

(See `crypto_envelope_v1.md` for how canonical bytes are used.)

---

## 2. Login Request Payload

### 2.1 Type
`type` MUST equal:

- `"login_request"`

### 2.2 Required Fields

A login request payload MUST include:

- `type` (string) = `"login_request"`
- `service_id` (string) — relying party identifier (e.g. domain)
- `nonce` (string) — unpredictable challenge supplied by the relying party
- `callback_url` (string) — where the wallet/app returns the response
- `version` (string) — protocol version label (default `"1"`)

### 2.3 Validation Rules (Fail-Closed)

A verifier MUST reject the payload if:

- any required field is missing
- any required field is not a string
- `type != "login_request"`
- `service_id` is empty after trimming
- `nonce` is empty after trimming
- `callback_url` is empty after trimming

No silent coercion is permitted.

---

## 3. Login Response Payload

A login response is the message the wallet/app signs and returns to the relying party.

### 3.1 Type
`type` MUST equal:

- `"login_response"`

### 3.2 Required Fields

A login response payload MUST include:

- `type` (string) = `"login_response"`
- `service_id` (string) — MUST match the login request `service_id`
- `nonce` (string) — MUST match the login request `nonce`
- `address` (string) — wallet address claimed by the user
- `pubkey` (string) — public key material (format defined by implementation)
- `version` (string) — protocol version label (default `"1"`)

### 3.3 Optional Fields

- `key_id` (string) — optional stable identifier for key rotation / selection

### 3.4 Binding Rules (Fail-Closed)

A verifier MUST reject the login response if:

- any required field is missing
- any required field is not a string
- `type != "login_response"`
- `service_id` does not exactly match the request `service_id`
- `nonce` does not exactly match the request `nonce`

---

## 4. Signing & Verification

- The login response payload MUST be signed using **Crypto Envelope v1**.
- `alg` identifiers MUST match those defined/accepted by the implementation.
- Verification MUST be fail-closed:
  - any parse error => reject
  - any mismatch => reject
  - no downgrade or fallback (see backend rules in implementation)

---

## 5. Security Notes (Non-Normative)

- Nonce MUST be unique per login attempt.
- Service binding prevents replay across services.
- Callback URL validation is intentionally minimal at contract level; higher layers
  MAY enforce stricter URL allowlists.

---

**Author:** DarekDGB  
**License:** MIT (2025)
