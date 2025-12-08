# DigiByte Q-ID — Examples Guide

Status: **draft – reference usage**

This document explains the small example programs shipped with the
DigiByte Q-ID repo and how they tie together the core modules.

---

## 1. Overview

The `examples/` folder is **not** production code.  
It is a teaching and smoke-testing layer that shows how to:

- Build a Q-ID login request URI on the service side.
- Let a wallet (Adamantine-style) prepare a signed login response.
- Verify that signed response on the server.

Currently we ship:

- `examples/login_roundtrip.py` – full end-to-end login flow in one file.

More examples can be added over time (registration, multi-key / PQC
backends, Guardian integration, etc.).

---

## 2. Example: `login_roundtrip.py`

Path:

```text
examples/login_roundtrip.py
```

Key pieces used:

- `qid.integration.adamantine.QIDServiceConfig`
- `qid.integration.adamantine.build_qid_login_uri`
- `qid.integration.adamantine.prepare_signed_login_response`
- `qid.integration.adamantine.verify_signed_login_response_server`
- `qid.crypto.QIDKeyPair` (dev HMAC backend)

### 2.1. What it simulates

1. **Service** creates a `QIDServiceConfig`:

   - `service_id` – stable identifier for the relying party.
   - `callback_url` – where the wallet should POST the response.

2. **Service** generates a `qid://login?...` URI with a fresh `nonce`.

3. **Wallet** (simulated) uses `prepare_signed_login_response(...)`:

   - Builds the login response payload.
   - Signs it with a dev HMAC `QIDKeyPair`.

4. **Service** verifies the response:

   - Calls `verify_signed_login_response_server(...)`.
   - If verification passes, it would create a user session.

The script prints:

- The login URI.
- The response payload JSON.
- The signature.
- The final verification result.

### 2.2. Why HMAC?

For simplicity, the example uses a **dev HMAC backend**:

- Easy to run anywhere.
- No external crypto dependency.

This is **not** meant for production. Real deployments will:

- Use a PQC / hybrid backend (ML-DSA, Falcon, etc.).
- Store secret keys in secure storage (HSM / vault / OS keystore).
- Keep secret keys on the wallet side, with services only holding
  verification keys.

---

## 3. Running the example locally

From the repo root, with Python 3.11+:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python examples/login_roundtrip.py
```

You should see output similar to:

- A `qid://login?d=...` URI.
- A JSON payload for `login_response`.
- A base64url signature string.
- `Server verification result: True`.

If verification fails, the example will print a failure message instead.

---

## 4. Relationship to the main docs

The examples connect directly to:

- **`docs/qid-spec.md`** – describes the protocol messages.
- **`docs/qid-api-server.md`** – describes server integration patterns.
- **`docs/qid-crypto-backends.md`** – explains how different crypto
  backends plug in.
- **`docs/qid-server-guide.md`** – end-to-end server integration guide.

Think of `examples/` as the “live code appendix” for those docs.

---

## 5. Extending the examples

Future additions might include:

- `examples/registration_roundtrip.py` – show service registration.
- `examples/pqc_backend_demo.py` – once a PQC backend is implemented.
- `examples/guardian_integration_stub.py` – sketch how Guardian /
  Shield might consume Q-ID events.

Contributors are encouraged to:

- Keep examples small and focused.
- Avoid external dependencies beyond what the main package already uses.
- Treat `examples/` as a place to **teach** and **experiment**, not a
  production API surface.
