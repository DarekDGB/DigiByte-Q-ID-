# Hybrid Key Container v1 Contract

Author: DarekDGB  
License: MIT (2025)

## Status
**Normative contract** — defines strict hybrid key handling.

## Purpose
This contract defines how **hybrid cryptographic keys** are represented and validated
within DigiByte Q-ID.

Hybrid keys require **two independent cryptographic assurances**:
- Classical / interim security
- Post-quantum security

## Supported Algorithms
- `pqc-ml-dsa`
- `pqc-falcon`
- `pqc-hybrid-ml-dsa-falcon`

## Hybrid Key Requirements
A hybrid key container MUST:
- Contain two independent secret components
- Bind each component to a specific algorithm
- Prevent partial usage

## Logical Structure (Conceptual)

```json
{
  "type": "hybrid-key-v1",
  "components": {
    "pqc-ml-dsa": "<key-material>",
    "pqc-falcon": "<key-material>"
  }
}
```

> This structure is **conceptual**. Concrete encoding is implementation-defined
> but MUST preserve one-to-one component mapping.

## Signing Rules
- Both components MUST sign the same canonical payload
- Both signatures MUST be present
- Failure of either component invalidates the signature

## Verification Rules
Verification MUST fail if:
- One component is missing
- Algorithms mismatch
- Any signature fails
- Encoding is malformed

## No Downgrade Rule
- Hybrid keys MUST NOT be treated as single-algorithm keys
- Hybrid verification MUST NOT fall back to a single signature

## Forward Compatibility
Future hybrid containers MUST:
- Use a new version identifier
- Preserve strict AND semantics
