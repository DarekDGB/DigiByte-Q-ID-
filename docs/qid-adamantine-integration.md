# DigiByte Q-ID — Adamantine Wallet Integration

Status: **draft – reference integration sketch**

This document describes how the DigiByte **Adamantine Wallet** can use
the Q-ID library to:

1. Build Q-ID **login request URIs** for services.
2. Create and sign **login responses** using the wallet's keys.
3. Provide a simple server-side verification flow for integrators.

The reference code lives in:

- `qid/integration/adamantine.py`

It is intentionally minimal and framework-agnostic so that mobile / web /
desktop clients can reuse the same ideas.

---

## 1. Concepts

### 1.1 Service configuration

Each relying party (website / app / service) that wants Q-ID login is
represented by a simple configuration object:

- `service_id` – stable identifier for the service
  (e.g. `"example.com"`, `"com.exchange.app"`).
- `callback_url` – HTTPS endpoint that receives Q-ID responses.

In the reference module this is modeled as:

```python
@dataclass
class QIDServiceConfig:
    service_id: str
    callback_url: str
```

Wallet code (Adamantine) can keep a list of known `QIDServiceConfig`
entries (bookmarks, saved logins, etc.).

### 1.2 Key management

Adamantine is expected to manage one or more **Q-ID keypairs** in its
secure storage (device keystore, hardware, etc.).

For now, the integration uses the **dev backend**:

- `qid.crypto.generate_dev_keypair()`
- `qid.crypto.sign_payload(...)`

Later, the same API can be backed by PQC / hybrid schemes without
changing how the wallet calls it.

---

## 2. Building a login request URI (wallet → service)

When a user chooses "Login with DigiByte Q-ID" to a given service,
Adamantine should:

1. Generate a **fresh nonce**.
2. Use the service configuration (service_id, callback_url).
3. Build a Q-ID login request payload.
4. Encode it into a `qid://login?...` URI.
5. Show it as a **QR code** or deep-link.

Reference helper:

```python
from qid.integration.adamantine import build_qid_login_uri
```

Flow:

```python
uri = build_qid_login_uri(
    service=config,
    nonce="random-nonce",
)
```

The `uri` can be:

- Rendered as a QR code for a browser-based service, or
- Used as an internal deep-link inside mobile flows.

---

## 3. Creating a signed login response (wallet side)

After the service shows a Q-ID login request (QR or deep-link), the
wallet:

1. **Parses** the login request URI.
2. Validates that `service_id` and `callback_url` match expectations.
3. Chooses the **DigiByte address** + **Q-ID keypair** to use.
4. Builds a **login response payload** from the request.
5. Signs the payload with `qid.crypto.sign_payload(...)`.
6. Sends the response + signature to the service's callback URL.

Reference helper:

```python
from qid.integration.adamantine import prepare_signed_login_response
```

Usage:

```python
response_payload, signature = prepare_signed_login_response(
    service=config,
    login_uri=uri_from_service,
    address=selected_address,
    keypair=wallet_keypair,
    key_id="primary",  # optional
)
```

The wallet then sends a POST to the callback URL, for example:

```json
{
  "qid_version": "1",
  "login_request_uri": "qid://login?d=...",
  "response_payload": { ... },
  "signature": "base64url-signature"
}
```

The exact HTTP/JSON shape is up to the integrator; Q-ID only specifies
the **cryptographic core**.

---

## 4. Server-side verification (service / backend)

On the service side, developers can:

1. Receive the login request URI, response payload and signature.
2. Decode the request.
3. Run a **reference verification flow**.

Reference helper:

```python
from qid.integration.adamantine import verify_signed_login_response_server
```

This internally uses:

- `parse_login_request_uri(...)`
- `server_verify_login_response(...)`
- the chosen `QIDKeyPair` / backend.

If verification succeeds, the service can:

- Create / resume a user session.
- Bind the Q-ID identity to an internal account.
- Log the event for audit / anomaly detection.

---

## 5. Guardian / Shield hooks (future)

Adamantine + Q-ID sit inside a larger defensive architecture
(**Guardian**, **QWG**, **Sentinel**, **DQSN**, **ADN**, **Adaptive Core**).

Future integration ideas:

- Every successful Q-ID login can emit a **signed event** that Guardian
  consumes for:
  - policy checks,
  - anomaly detection,
  - correlation with on-chain activity.
- Repeated failed verifications from the same service / device can
  trigger:
  - risk scores,
  - alerts,
  - temporary lockouts.

These hooks can be added around the helpers in
`qid.integration.adamantine` without changing the core Q-ID protocol.

---

## 6. Summary

The Adamantine integration layer aims to:

- Keep **wallet code simple** (build URI, sign response, verify).
- Make **server integration predictable**, via a clear reference flow.
- Stay compatible with future **PQC crypto backends** and with the
  larger **DigiByte Quantum Shield** stack.

All complexity around keys, storage, PQC algorithms and policies can
evolve behind the stable helpers exposed by:

```python
qid.integration.adamantine
qid.crypto
qid.protocol
```

This lets Q-ID grow from a dev prototype into a production-grade,
quantum-aware authentication layer for the entire DigiByte ecosystem.
