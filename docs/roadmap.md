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
- NIP-46 decrypted payload bridge vectors for companion conformance tests.
- JSON schemas.
- Deterministic Nostr/BIP-340 fixtures.

Status: active. The first ESP32-S3 scaffold capability vector and
display-oriented review-screen, QR review transcript, and NIP-46 decrypted
payload bridge vectors are implemented.

## M3: Transport Contracts

- Capability discovery draft.
- Transport-independent response verification requirements.

## Later

- Full encrypted NIP-46 relay/session mapping.
- Firmware conformance vectors.
