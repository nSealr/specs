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
- JSON schemas.
- Deterministic Nostr/BIP-340 fixtures.

Status: active. The first ESP32-S3 scaffold capability vector,
display-oriented review-screen, QR review transcript, NIP-46 decrypted payload
bridge vectors, NIP-46 `connect` policy-review intent vector, explicit
NIP-46 permission policy vectors, NIP-46 bridge decision vectors, and
read-only NIP-46 policy-file vector/schema are implemented.

## M3: Transport Contracts

- Capability discovery draft.
- Transport-independent response verification requirements.

## Later

- Full encrypted NIP-46 relay/session mapping.
- Firmware conformance vectors.
