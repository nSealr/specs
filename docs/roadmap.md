# Roadmap

## M1: Specs Foundation

- Signing request v0.
- Signing response v0.
- Common error response.
- QR envelope v0.
- Serial frame v0.
- Smartcard APDU v0.
- Capability discovery and disabled-signing request/response vectors for
  scaffolded direct devices.
- Trusted review and review-screen vectors for display-oriented approval flows.
- QR review transcript vectors for display/button adapter acceptance tests.
- NIP-46 decrypted payload bridge and `connect` policy-review intent vectors
  for companion conformance tests.
- NIP-46 permission requirement and permission-check decision vectors for
  explicit policy-matching conformance.
- NIP-46 bridge decision vectors for permitted signer routing, local `ping`,
  `connect` review, and deterministic permission-denied responses.
- NIP-46 read-only policy-file vectors for explicit approved permissions.
- NIP-46 read-only policy-file JSON schema.
- NostrSeal v0 implementation limit profile for constrained signer safety.
- Malicious/rejection vectors for unsafe signing requests, unsafe responses, QR
  envelopes, serial frames, invalid device request metadata, NIP-46 payloads,
  and policy files.
- JSON schemas.
- Deterministic Nostr/BIP-340 fixtures.

Status: active. The first ESP32-S3 scaffold capability vector,
display-oriented review-screen, QR review transcript, NIP-46 decrypted payload
bridge vectors, NIP-46 `connect` policy-review intent vector, explicit
NIP-46 permission policy vectors, NIP-46 bridge decision vectors, and
read-only NIP-46 policy-file vector/schema are implemented. The v0
implementation limit profile and initial malicious/rejection vectors are now
part of the shared contract.

## M3: Transport Contracts

- Capability discovery draft.
- Transport-independent response verification requirements.

## M4.5/M7.5: Pre-Signing Contract Hardening

- Define named NostrSeal v0 parser and resource limits in one contract.
- Add shared invalid vectors for event-template signed fields, unsafe integer
  values, oversized content/tags/messages, malformed or ambiguous responses,
  malformed QR envelopes, malformed serial frames, invalid device request
  metadata, malformed NIP-46 payloads, and invalid policy files.
- Keep these as NostrSeal implementation safety limits for constrained
  signers, not Nostr protocol limits.
- Require companion, Raspberry, and ESP32 implementations to consume the
  vectors where their parsers support the relevant boundary before real signing
  or full NIP-46 sessions are enabled.

Status: contract implementation in progress. The specs profile and initial
invalid vectors are implemented; downstream companion, Raspberry, ESP32, and
lab consumers must still enforce or smoke-test the applicable vectors before
this gate can unblock ESP32 real signing, browser extension/full NIP-46
sessions, persistent grants, production smartcard claims, or custom
persistent-secret hardware-wallet claims.

Status note, 2026-05-08: invalid serial-frame vectors now include valid
transport frames with invalid decoded request metadata for unsupported
`version` and invalid `request_id` syntax. Device transports must reject these
before request handling or signing paths.

## Later

- Full encrypted NIP-46 relay/session mapping.
- Firmware conformance vectors.
