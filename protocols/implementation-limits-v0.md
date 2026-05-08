# Implementation Limits v0

NostrSeal v0 uses a named safety profile for constrained signers. These are
NostrSeal implementation limits, not Nostr protocol limits. They bound what
pre-production NostrSeal firmware and companion tooling must accept before
review, approval, or signing.

The canonical machine-readable profile is:

- `vectors/limits/nseal-v0.json`
- `format`: `nostrseal-implementation-limits-v0`
- `name`: `nostrseal-v0`

## Limits

| Limit | Value | Applies to |
| --- | ---: | --- |
| `max_request_id_length` | 128 | Signing request and NIP-46 request ids. |
| `max_decoded_request_json_bytes` | 704 | Compact UTF-8 decoded NostrSeal request JSON. |
| `max_static_qr_decoded_json_bytes` | 704 | Static QR envelope decoded UTF-8 JSON payloads. |
| `max_serial_frame_bytes` | 1024 | Complete ASCII serial frame line. |
| `max_nip46_decrypted_message_json_bytes` | 1024 | Already-decrypted NIP-46 request message JSON. |
| `max_content_utf8_bytes` | 512 | `event_template.content`. |
| `max_tag_count` | 16 | `event_template.tags` entries. |
| `max_tag_fields_per_tag` | 8 | Fields in each tag array. |
| `max_tag_field_utf8_bytes` | 64 | Each individual tag string field. |
| `max_total_tag_utf8_bytes` | 4096 | Sum of UTF-8 bytes across all tag string fields. |
| `max_safe_integer` | 9007199254740991 | Integer safety bound for `created_at` and `kind`. |

## Integer Policy

`created_at` and `kind` must be JSON integers, must not be booleans, must be
greater than or equal to `0`, and must be less than or equal to
`max_safe_integer`.

Floats, strings, negative values, and integers above the safe-integer bound are
rejected before review or signing.

## Change Control

Changing these values requires:

1. Updating `vectors/limits/nseal-v0.json`.
2. Updating malicious/rejection vectors when behavior changes.
3. Updating companion, Raspberry, and ESP32 conformance tests.
4. Keeping ESP32 production signing disabled until all affected parser,
   display-review, physical-approval, custody, and verification gates pass.
