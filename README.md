# nSealr Specs

Shared specifications for nSealr signers and compatible implementations.

This repository will define the interfaces that every hardware line and
companion implementation must agree on:

- NIP-01 event canonicalization and signing fixtures.
- BIP-340/secp256k1 test vectors.
- Static and animated QR signing request/response envelopes.
- USB and serial signer transport protocol.
- JavaCard/APDU smartcard contract.
- JSON schemas and example request/response payloads.

## Current Scope

- Signing request protocol v0.
- Signing response protocol v0.
- Capability discovery request and ESP32-S3 scaffold response examples.
- ESP32-S3 scaffold signing-disabled response vector.
- Error object v0.
- Static `nsealr1:` and animated `nsealr1a:` QR envelope v0.
- Serial frame v0.
- Smartcard APDU v0.
- Deterministic Nostr/BIP-340 fixtures.
- Canonical NIP-06 account `0` mnemonic derivation test vector.
- SeedSigner Standard SeedQR and CompactSeedQR compatibility vectors for
  QR-vault BIP-39 session import. These vectors cover seed material for NIP-06
  Nostr derivation only, not Bitcoin descriptors, xpubs, PSBTs, or wallet
  policy.
- Trusted event review vectors for display-oriented signer flows.
- Trusted review-screen vectors with request-bound `approval_digest` values for
  display-oriented signer approval flows.
- Trusted review display-frame vectors with explicit display limits for bounded
  title/body/action rendering on small screens.
- Trusted review detail-page vectors with complete Event/Content/Tags/Decision
  physical pages, scroll-window indicators, compact line styles, visible
  JSON-style control escapes, and explicit codepoint fallback for constrained
  bitmap displays.
- QR review transcript vectors that bind raw QR input, displayed frames,
  physical-style button sequences, terminal decisions, and approval-gate state.
  They cover both simple screen-page traversal and detail-page scroll-window
  navigation for constrained displays.
- NIP-46 decrypted payload bridge vectors for `get_public_key`, `sign_event`,
  local `ping`, response mapping, deterministic `connect` review pages, and
  explicit permission requirement/check/bridge decision outputs. The
  `connect` review contract displays the remote signer pubkey, whether a
  secret was provided, and requested permissions without echoing the secret
  value or implying `ack`, relay sessions, NIP-44 handling, or stored grants.
- NIP-46 read-only policy-file vectors for explicit approved permissions used
  by companion decision harnesses.
- JSON schema for the read-only NIP-46 policy-file format.
- Identity, recovery, policy, grant descriptor, and policy-decision transcript
  vectors for secretless companion routing across the five signer families.
- Route-selection vectors that bind an account descriptor plus requested
  method to a secretless selected signer route without dispatching signer I/O.
- Account/custody product model for QR vault session keyrings, persistent
  device vaults, per-public-key policy authority, and SeedSigner-compatible
  SeedQR import vectors without turning policy records into Nostr events.
- JSON schemas for account descriptors, policy profiles, grant descriptors, and
  policy-decision and route-selection vectors.
- Feature conformance matrix for the five first-class signer families. The
  matrix records which features are required, optional, planned, forbidden, or
  not applicable per family, and enforces one shared behavior contract whenever
  a feature exists on more than one implementation.
- Named nSealr v0 implementation safety-limit profile for constrained
  signers.
- Shared malicious/rejection vectors for unsafe signing requests, QR envelopes,
  serial frames, invalid device request metadata, NIP-46 payloads, and NIP-46
  policy files. Serial-frame rejection vectors include checksum mismatch,
  malformed payload, oversized frames, unsupported frame types, and invalid
  decoded request metadata.
- Review edge-case vectors for unknown kinds, empty content, long content,
  event references, and high tag counts.
- Transport, device, review, review-screen, review-display-frame,
  review-detail-page, review-transcript, NIP-46, NIP-46 policy-file, SeedQR,
  account-descriptor, policy-profile, grant-descriptor, policy-decision,
  route-selection, feature-matrix, invalid-vector, limit-profile, and smartcard
  vectors shared by implementation repositories, including APDU success and
  deterministic status-word rejection cases.

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
