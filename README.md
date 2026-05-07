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
- Review edge-case vectors for unknown kinds, empty content, long content,
  event references, and high tag counts.
- Transport, device, review, review-screen, and smartcard vectors shared by
  implementation repositories.

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
