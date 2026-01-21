<!--
Author: DarekDGB
License: MIT (c) 2025
-->

# DigiByte Q-ID — CI & Contract Locking

**Author:** DarekDGB  
**License:** MIT (c) 2025

## Why we lock a contract

Q-ID is a security protocol. The most dangerous failures are “small” interface drift:
- parameters renamed
- argument order changed
- optional args added that alter behavior
- helpers promoted to public accidentally

To prevent this, Q-ID freezes an explicit **API surface contract**.

---

## API surface contract

The contract is stored at:

- `contracts/api_surface_v0_1.json`

It records:
- the public functions that are allowed
- the import path for each
- the positional arg names (order matters)
- the kwonly arg names (order matters)

CI enforces that the actual Python function signatures match the contract exactly.

This makes API drift **impossible to miss**.

---

## CI: pytest + coverage gate

CI runs:
- `pytest`
- `pytest-cov`
- coverage gate `≥ 90%`

Why coverage is enforced:
- security code must be exercised
- fail-closed paths must be tested (negative-first)
- regressions should be caught immediately

---

## Optional PQC workflow (real backend proof)

Real PQC depends on optional tooling (e.g., liboqs).
We do NOT want day-to-day CI blocked by platform availability.

So we keep:
- main CI: always runs, always deterministic
- optional PQC CI: runs when available, proves real backend paths

This yields:
- reproducible baseline everywhere
- real-crypto proof when the environment supports it

---

## Tags and releases

A “CI-locked baseline” tag is used as a reproducible reference point.

Once created:
- the tag should not be reused for a different state
- release notes can be edited, but the tag should remain a stable anchor

Recommendation:
- keep building on `main`
- cut new tags for meaningful milestones (e.g., `v0.1.1`, `v0.2.0`)

---

## Definition of “contract-locked”

A state is considered contract-locked when:
- tests are green
- coverage gate passes
- `api_surface_v0_1.json` is valid JSON and enforced
- no silent fallback exists for selected PQC backends
