# Q-ID URI Scheme v1

Author: DarekDGB  
License: MIT (2025)

## Status
Contract-locked (v1)

## Purpose
Defines the canonical URI entry points for DigiByte Q-ID.
These URIs are the **public boundary** of the protocol and must be stable.

## Supported Schemes

### Login
qid://login?d=<base64url(json)>

### Register
qid://register?d=<base64url(json)>

## Rules
- `qid://` scheme is mandatory
- Exactly one action segment (`login` or `register`)
- Payload MUST be base64url-encoded JSON
- No padding (`=`) allowed
- Unknown actions MUST be rejected
- Unknown query parameters MUST be ignored or rejected (implementation choice, but deterministic)

## Security Properties
- Deterministic parsing
- No network side effects
- Fail-closed on malformed input

## Versioning
Breaking changes require `v2` document and new URI action.

