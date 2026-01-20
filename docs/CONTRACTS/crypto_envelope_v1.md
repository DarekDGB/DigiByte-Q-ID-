<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# Crypto Envelope v1 Contract

Author: DarekDGB  
License: MIT (2025)

## Status
**Normative contract** — tests and code must conform to this document.

## Purpose
This contract defines the **Crypto Envelope v1** format used by DigiByte Q-ID for all signatures.

The envelope:
- Is deterministic
- Is explicit about algorithms
- Is fail-closed
- Allows future versioning without ambiguity

## Envelope Encoding
- Canonical JSON (sorted keys, no whitespace)
- UTF-8 bytes
- Base64 encoded as the transport string

## Envelope Structure

```json
{
  "v": 1,
  "alg": "<algorithm-id>",
  "sig": "<base64-signature>"
}
```

### Hybrid Envelope Variant

```json
{
  "v": 1,
  "alg": "pqc-hybrid-ml-dsa-falcon",
  "sigs": {
    "pqc-ml-dsa": "<base64-signature>",
    "pqc-falcon": "<base64-signature>"
  }
}
```

## Required Fields
- `v` — Envelope version (MUST be `1`)
- `alg` — Algorithm identifier (normalized)
- `sig` / `sigs` — Signature material

## Algorithm Rules
- Algorithm IDs are **explicit**
- No implicit downgrade
- Legacy identifiers must be normalized before verification

## Verification Rules
Verification MUST fail if:
- Envelope version is unknown
- Algorithm mismatches keypair
- Any required field is missing
- Base64 decoding fails
- Hybrid signature set is incomplete

## Fail-Closed Guarantee
Under no circumstance may an invalid envelope:
- Be partially accepted
- Fall back to another algorithm
- Be reinterpreted

## Versioning
Future envelopes MUST:
- Increment `v`
- Never change v1 semantics
