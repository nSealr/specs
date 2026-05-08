# QR Envelope v0

The first QR envelope is intentionally simple.

## Format

```text
nseal1:<base64url-json>
```

- Prefix: `nseal1:`.
- Payload: unpadded base64url of UTF-8 JSON.
- Compression: none in v0.
- Animated QR: out of scope for M1.

## Decoding

1. Require the `nseal1:` prefix.
2. Decode unpadded base64url payload.
3. Parse UTF-8 JSON.
4. Validate the decoded object against the relevant request or response schema.
5. Enforce the NostrSeal v0 implementation safety profile before review or
   signing.

Static QR payloads whose decoded JSON exceeds
`max_static_qr_decoded_json_bytes` are rejected in v0. The base64url payload is
unpadded; padded payloads are rejected.

## Security Notes

The QR envelope provides transport framing, not trust. The signer must still
parse the request, compute the event id, render review where possible, require
approval, and sign only after approval.
