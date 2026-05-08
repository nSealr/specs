# NostrSeal Specs

Shared specifications for NostrSeal signers and compatible implementations.

This repository will define the interfaces that every hardware line and
companion implementation must agree on:

- NIP-01 event canonicalization and signing fixtures.
- BIP-340/secp256k1 test vectors.
- QR signing request envelope.
- USB and serial signer transport protocol.
- JavaCard/APDU smartcard contract.
- JSON schemas and example request/response payloads.

## Current Scope

- Signing request protocol v0.
- Signing response protocol v0.
- Capability discovery request and ESP32-S3 scaffold response examples.
- ESP32-S3 scaffold signing-disabled response vector.
- Error object v0.
- QR envelope v0.
- Serial frame v0.
- Smartcard APDU v0.
- Deterministic Nostr/BIP-340 fixtures.
- Canonical NIP-06 account `0` mnemonic derivation test vector.
- Trusted event review vectors for display-oriented signer flows.
- Trusted review-screen vectors with request-bound `approval_digest` values for
  display-oriented signer approval flows.
- Trusted review display-frame vectors with explicit display limits for bounded
  title/body/action rendering on small screens.
- QR review transcript vectors that bind raw QR input, displayed frames,
  physical-style button sequences, terminal decisions, and approval-gate state.
- NIP-46 decrypted payload bridge vectors for `get_public_key`, `sign_event`,
  local `ping`, response mapping, `connect` policy-review intents, and
  explicit permission requirement/check/bridge decision outputs.
- NIP-46 read-only policy-file vectors for explicit approved permissions used
  by companion decision harnesses.
- JSON schema for the read-only NIP-46 policy-file format.
- Named NostrSeal v0 implementation safety-limit profile for constrained
  signers.
- Shared malicious/rejection vectors for unsafe signing requests, QR envelopes,
  serial frames, NIP-46 payloads, and NIP-46 policy files.
- Review edge-case vectors for unknown kinds, empty content, long content,
  event references, and high tag counts.
- Transport, device, review, review-screen, review-display-frame,
  review-transcript, NIP-46, NIP-46 policy-file, invalid-vector, limit-profile,
  and smartcard vectors shared by implementation repositories.

## Initial Layout

- `protocols/`: human-readable protocol specifications.
- `vectors/`: canonical test vectors and expected signatures.
- `schemas/`: JSON schemas and machine-readable validation artifacts.
- `examples/`: sample requests, signed events, and failure cases.

## Quality Baseline

Run the repository verification loop with:

```sh
make ci
```

## License

Specifications, schemas, examples, fixtures, and test vectors are released
under CC0-1.0 unless a file says otherwise. Future helper scripts may use MIT
when code-specific licensing is useful.
