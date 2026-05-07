# Signing Response Protocol v0

Every response echoes the request version and request id.

## Successful Capabilities Response

```json
{
  "version": 1,
  "request_id": "req-capabilities-esp32-s3-scaffold",
  "ok": true,
  "result": {
    "capabilities": {
      "device": {
        "name": "NostrSeal ESP32-S3 USB Signer Scaffold",
        "firmware": "nostrseal-esp32-s3-usb-signer",
        "hardware": "esp32-s3-devkitc-1"
      },
      "protocols": ["nseal.signing.v0", "nseal.serial-frame.v0"],
      "methods": ["get_capabilities", "get_public_key", "sign_event"],
      "transports": ["usb-serial-jtag"],
      "signing_enabled": false,
      "requires_physical_approval": true
    }
  }
}
```

`signing_enabled: false` means the device may advertise the future signing
method while still rejecting `sign_event` until storage, trusted review, and
physical approval gates are implemented.

## Successful Public Key Response

```json
{
  "version": 1,
  "request_id": "req-pubkey-1",
  "ok": true,
  "result": {
    "public_key": "<64 lowercase hex chars>"
  }
}
```

## Successful Event Signing Response

```json
{
  "version": 1,
  "request_id": "req-kind-1-basic",
  "ok": true,
  "result": {
    "event": {
      "id": "<64 lowercase hex chars>",
      "pubkey": "<64 lowercase hex chars>",
      "created_at": 1710000000,
      "kind": 1,
      "tags": [],
      "content": "NostrSeal fixture: basic kind 1 event.",
      "sig": "<128 lowercase hex chars>"
    }
  }
}
```

The companion must verify:

- response `request_id` matches the request;
- signed event fields match the requested template;
- event id matches NIP-01 canonical serialization;
- signature verifies against event id and public key.

## Error Response

```json
{
  "version": 1,
  "request_id": "req-kind-1-basic",
  "ok": false,
  "error": {
    "code": "user_rejected",
    "message": "User rejected the signing request.",
    "retryable": true
  }
}
```

Error responses must not include `result`.
