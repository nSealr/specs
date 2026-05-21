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
- NIP-19 `nsec` private-key import vectors for RAM-only QR vault session
  loading. These vectors cover migration/recovery inputs only; they are not
  persistent key slots, policy records, mnemonics, or NIP-49 encrypted backups.
- Secret-hidden session import review vectors for RAM-only QR vault source
  loading. These vectors pin the review pages, source fingerprint, and import
  approval digest for SeedQR/BIP-39 and NIP-19 `nsec` inputs without exposing
  mnemonic words, raw private keys, persistence, derivation, or signing
  approval.
- Source public-key proof vectors for RAM-only QR vault sources. These vectors
  pin the expected public key derived from a reviewed NIP-06 BIP-39 source or a
  NIP-19 `nsec` source, so descriptors and source fingerprints cannot stand in
  for derivation before signing.
- Feature contract for local RAM-only session-source generation on stateless QR
  vaults. The v0 contract covers generated BIP-39 mnemonic sources and
  standalone NIP-19 `nsec`-equivalent private-key sources; it does not define
  persistent key slots or automated policy.
- Danger-zone session-source backup review vectors for generated or imported
  RAM-only QR vault sources. The review pages are secret-hidden and require
  explicit physical approval before a BIP-39 words/SeedQR or NIP-19 `nsec`
  backup payload can be revealed for user recovery.
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
  local `ping`, local `switch_relays` no-change metadata, response mapping,
  deterministic `connect` review pages, and explicit permission
  requirement/check/bridge decision outputs. The
  `connect` review contract displays the remote signer pubkey, whether a
  secret was provided, and requested permissions without echoing the secret
  value. It now also carries a digest-bound local approval artifact that proves
  which review was approved, without implying `ack`, relay sessions, NIP-44
  handling, or stored grants.
- NIP-46 read-only policy-file vectors for explicit approved permissions used
  by companion decision harnesses.
- NIP-46 connection URI vectors for descriptor-only `bunker://` and
  `nostrconnect://` token parsing without relay sessions, grant creation, or
  secret echo.
- NIP-46 connection token response vectors for `nostrconnect://` flows. They
  verify the returned secret value against the local token without storing or
  echoing it, discover the remote signer pubkey from the response envelope, and
  still forbid relay I/O, NIP-44 derivation, `connect` acknowledgement, grant
  creation, signer dispatch, production secret storage, or session persistence.
- NIP-46 relay event envelope vectors for `kind:24133` request/response events.
  These validate sender pubkey, exactly one recipient `p` tag, opaque encrypted
  content, tag arrays made only of strings, and optional signed relay-event
  fields. When signed fields are present, the envelope contract verifies the
  NIP-01 event id and BIP-340 relay event signature without opening relays,
  decrypting NIP-44 content, creating grants, or dispatching to signers.
- NIP-46 relay step vectors for deterministic post-decryption request and
  response handling. Request steps bind an already validated relay event
  envelope, an already decrypted NIP-46 message, and reviewed permissions;
  response steps shape-check plaintext signed-event, public-key, connect ack,
  switch-relays, ping, auth challenge, and error responses. Auth challenges
  expose only safe http(s) URL metadata without credentials or fragments for
  later UI and do not open the URL. Connect ack and switch-relays results
  remain metadata-only and do not activate or mutate a session. These vectors
  verify signed relay event envelopes while still avoiding opening relays,
  decrypting NIP-44 content, acknowledging `connect`, creating grants,
  dispatching signers, or persisting session state.
- NIP-46 auth challenge review vectors for the step after response metadata
  normalization. They bind the page-visible auth URL, remote signer pubkey,
  client pubkey, and manual approval digest while still forbidding automatic
  URL opening, relay I/O, `connect` acknowledgement, grant creation, signer
  dispatch, secret storage, or session persistence.
- NIP-46 session lifecycle checkpoint vectors for the next pre-production
  boundary after manual `connect` approval. These vectors bind client/signer
  pubkeys, relays, reviewed connect digest, approval time, expiry, requested
  permissions, and approved permission subsets while still forbidding secret
  material, NIP-44 key derivation, relay I/O, `connect` acknowledgement, grant
  creation, signer dispatch, production secret storage, and session
  persistence.
- NIP-46 pending-session request gate vectors for the follow-on boundary after
  an `approved_pending_ack` checkpoint exists. They bind a decrypted request to
  the reviewed session and relay event, then deterministically reject signer
  dispatch with `connect_ack_pending` until a future acknowledged session
  contract exists. Invalid vectors pin sender/recipient mismatches,
  pre-approval and expired evaluation timestamps, wrong direction, and
  attempted `connect` processing.
- JSON schema for the read-only NIP-46 policy-file format. Approved
  `sign_event` entries must be kind-scoped; broad `sign_event` is only
  requested-permission metadata.
- Identity, recovery, policy, grant descriptor, policy-change review, and
  policy-decision transcript vectors for secretless companion routing across
  the five signer families, plus an external NIP-46 adapter route. Descriptor
  schemas are closed and pin `policy-*` / `grant-*` identifiers so ignored
  metadata cannot become later routing or policy semantics. nSealr-managed
  grant descriptors are limited to persistent policy routes with device
  confirmation: ESP32 USB/NIP-46 and custom hardware wallets. The v0 grant
  automation menu is limited to `sign_event` kind `1`; grants are temporary
  scoped session records with expiry, rate limits, revocation, and audit, not
  a separate grant-decision-mode system. Broader automated signing remains
  future-spec work.
- Route-selection vectors that bind each shared account descriptor plus a
  requested method to a secretless selected signer route without dispatching
  signer I/O. NIP-06 account descriptors also bind to the same reviewed source
  fingerprint used by RAM-only import review.
- Route-refusal contract vectors for local companion dispatch before production
  signer drivers exist. They require deterministic non-retryable
  `signer_route_unavailable` behavior when a route has no dispatcher, require
  display-less smartcard routes to fail first on missing or mismatched external
  review acknowledgement, and require trusted-review routes to reject external
  review acknowledgements instead of treating the companion as review
  authority.
- Access-surface vectors for stable companion-facing adapters that are not
  signer families. The current vector pins a NIP-07 browser provider over the
  local companion service: authorized route selection returns the selected
  public key, signer dispatch is not attempted without an explicit dispatcher,
  and the browser surface remains secretless.
- Account/custody product model for QR vault session keyrings, persistent
  device vaults, per-public-key policy authority, and SeedSigner-compatible
  SeedQR import vectors without turning policy records into Nostr events.
- Persistent-secret custody contract for the custom hardware-wallet family.
  The v0 contract pins no plaintext secrets at rest, wrapped/encrypted storage
  candidates, ESP32-S3 RAM-only unlock, required wipe events,
  MAC-and-Destroy PIN hardening, and disabled-by-default backup/export review
  gates without claiming production storage or direct TROPIC01 BIP-340 support.
- JSON schemas for account descriptors, policy profiles, grant descriptors,
  policy-change reviews, and policy-decision and route-selection vectors,
  including route-type dependent constraints for account descriptors and
  route-selection metadata.
- Feature conformance matrix for the five first-class signer families. The
  matrix records which features are required, optional, planned, forbidden, or
  not applicable per family, and enforces one shared behavior contract whenever
  a feature exists on more than one implementation.
- Named nSealr v0 implementation safety-limit profile for constrained
  signers.
- Shared malicious/rejection vectors for unsafe signing requests, QR envelopes,
  serial frames, invalid device request metadata, NIP-46 payloads, and NIP-46
  policy files, malformed NIP-46 connection URIs, and invalid NIP-46
  relay-step auth URLs and connection token responses. Serial-frame rejection
  vectors include checksum mismatch, malformed payload, oversized frames,
  unsupported frame types, and invalid decoded request metadata.
- Review edge-case vectors for unknown kinds, empty content, long content,
  event references, and high tag counts.
- Transport, device, review, review-screen, review-display-frame,
  review-detail-page, review-transcript, NIP-46, NIP-46 policy-file, NIP-46
  connection URI, SeedQR, NIP-19 `nsec`, session-import-review,
  session-source-backup, NIP-46 session lifecycle, NIP-46 session gate,
  account-descriptor, policy-profile, grant-descriptor, policy-change review,
  policy-decision, persistent-secret custody,
  route-selection, access-surface, feature-matrix, invalid-vector,
  limit-profile, and smartcard vectors shared
  by implementation repositories, including APDU success and deterministic
  status-word rejection cases.

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
