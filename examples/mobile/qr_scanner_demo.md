# DigiByte Q-ID — Mobile QR Scanner Demo

**Status:** developer guidance / integration example**  
**Folder:** `examples/mobile/qr_scanner_demo.md`

This document explains how a mobile wallet (iOS or Android) can:

1. Scan a **Q-ID login QR code**  
2. Extract the embedded `qid://login?...` URI  
3. Decode the Base64 → JSON payload  
4. Build a **signed login response** using Q-ID keys  
5. POST it back to the service callback URL  

This is NOT a full mobile app — it is a clear technical guide for developers.

---

# 1. Q-ID QR CODE FORMAT

A Q-ID login request is encoded as a URI:

```
qid://login?d=<base64url(JSON)>
```

Example JSON inside the Base64 payload:

```json
{
  "type": "login_request",
  "service_id": "example.com",
  "nonce": "abc123",
  "callback_url": "https://example.com/qid/callback",
  "version": "1"
}
```

A wallet must:

- Detect scheme `qid://`
- Decode the Base64 `d=` parameter
- Validate `service_id` + `callback_url`
- Build a login response payload
- Sign it using `qid.crypto`
- POST it back to the callback URL

---

# 2. Python Example — Generating a Q-ID QR Code

This example shows how any service can generate a Q-ID QR code for mobile wallets:

```python
from qid.protocol import build_login_request_payload, build_login_request_uri
import qrcode

payload = build_login_request_payload(
    service_id="example.com",
    nonce="abc123",
    callback_url="https://example.com/qid/callback",
)

uri = build_login_request_uri(payload)

img = qrcode.make(uri)
img.save("qid_login_qr.png")
print("Saved QR code to qid_login_qr.png")
```

This QR code contains the full Q-ID login request.

---

# 3. iOS Swift — QR Scanner Pseudocode

Below is real Swift pseudocode for an iOS wallet:

```swift
import AVFoundation

func startScanner() {
    let session = AVCaptureSession()
    // Configure camera + metadata
    let output = AVCaptureMetadataOutput()
    output.setMetadataObjectsDelegate(self, queue: .main)
    output.metadataObjectTypes = [.qr]
}

func metadataOutput(_ output: AVCaptureMetadataOutput,
                    didOutput metadataObjects: [AVMetadataObject],
                    from connection: AVCaptureConnection) {

    guard let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
          let text = obj.stringValue else { return }

    if text.starts(with: "qid://") {
        handleQIDLogin(uri: text)
    }
}

func handleQIDLogin(uri: String) {
    // Extract base64 payload after "d="
    guard let comps = URLComponents(string: uri),
          let d = comps.queryItems?.first(where: { $0.name == "d" })?.value,
          let jsonData = Data(base64URLEncoded: d) else { return }

    // Parse JSON
    let request = try! JSONDecoder().decode(QIDLoginRequest.self, from: jsonData)

    // Validate service fields, show UI confirmation to user...

    // Build login response
    let response = QIDLoginResponse(
        // Fill fields from request + wallet identity
    )

    // Sign response (pseudo)
    let signature = QIDCrypto.sign(response)

    // POST to callback
    postToCallback(url: request.callback_url, payload: response, signature: signature)
}
```

This shows the full scanning → decoding → verifying flow.

---

# 4. Android Kotlin — QR Scanner Pseudocode

Below is real Kotlin pseudocode for Android:

```kotlin
val scanner = GmsBarcodeScannerOptions.Builder()
    .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
    .build()

val client = GmsBarcodeScanning.getClient(context, scanner)

fun startScanner() {
    client.startScan()
        .addOnSuccessListener { barcode ->
            val text = barcode.rawValue ?: return@addOnSuccessListener
            if (text.startsWith("qid://")) {
                handleQIDLogin(text)
            }
        }
}

fun handleQIDLogin(uri: String) {
    // Parse URI
    val parsed = Uri.parse(uri)
    val base64 = parsed.getQueryParameter("d") ?: return

    // Decode Base64 → JSON
    val json = decodeBase64(base64)
    val request = gson.fromJson(json, QIDLoginRequest::class.java)

    // Build response
    val response = QIDLoginResponse(/* wallet identity */)

    // Sign response
    val signature = QIDCrypto.sign(response)

    // POST back
    postCallback(request.callback_url, response, signature)
}
```

This is what real Android integration will look like.

---

# 5. Architecture Notes

A real wallet *must* show the user:

- service name (`service_id`)
- callback URL
- request type (“Login request”)
- nonce (optional)

Key security requirements:

✔ Wallet must validate service_id  
✔ Wallet must refuse unknown or suspicious callback URLs  
✔ Keys must be stored in Secure Enclave / Android Keystore  
✔ Signing must require local user confirmation  
✔ Wallet must protect against phishing (lookalike domains)  

---

# 6. Summary

This demo provides:

- Python QR code generator  
- iOS Swift scanner pseudocode  
- Android Kotlin scanner pseudocode  
- Proper Q-ID decoding and response logic  

This file is a **developer-facing guide**, making Q-ID adoption easy for mobile wallets and simple applications.

Upload this file to:

```
examples/mobile/qr_scanner_demo.md
```

Then proceed to Step 4 (Threat Model expansion) when ready.
