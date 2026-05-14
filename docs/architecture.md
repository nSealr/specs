# Architecture

`nSealr/specs` is the canonical contract repository for every nSealr
signer implementation.

## Responsibilities

- Define signing request and response formats.
- Define signing-status diagnostics, including the distinction between missing
  real-signing gates and development-accepted gates that have deterministic
  coverage or manual development evidence but are not production claims.
  Signing-status responses must be non-contradictory: `signing_enabled: true`
  requires an empty `missing_gates` list, and `signing_enabled: false` requires
  at least one missing gate. Both gate lists must be duplicate-free.
- Define error formats and capability discovery.
- Define QR, serial, USB, and smartcard envelope semantics before
  implementation repositories depend on them.
- Publish deterministic fixtures for NIP-01 event ids and BIP-340 signatures.
- Publish deterministic SeedSigner Standard SeedQR and CompactSeedQR
  compatibility vectors for QR-vault BIP-39 session import. These vectors
  define how nSealr consumes SeedSigner-compatible seed material for NIP-06
  Nostr derivation; they do not import Bitcoin descriptors, xpubs, PSBTs, or
  wallet policy.
- Publish deterministic trusted-review vectors for event details that hardware
  displays must render before approval.
- Publish deterministic trusted review-screen vectors and approval digests that
  bind request metadata, exact event templates, review data, and rendered pages
  before signing.
- Publish deterministic trusted review display-frame vectors that pin bounded
  title, page indicator, body-line wrapping/truncation, and action-hint output
  for small trusted screens, including UTF-8 codepoint-boundary preservation
  during constrained wrapping.
- Publish deterministic trusted review detail-page vectors for complete
  physical review pages on constrained signers. These vectors preserve the
  existing `screen-pages` approval digest, but separately pin Event, Content,
  Tags, and Decision pages, scroll-window indicators, body-line styles, and
  display-safe text. JSON control characters decoded inside event strings must
  be rendered as visible JSON-style escapes such as `\n`, `\t`, `\r`, `\b`,
  and `\f`; unsupported display glyphs still use explicit `U+XXXX` fallback
  text. They are display conformance fixtures, not a replacement for the
  approval-digest contract. Their style metadata is part of the contract: if a
  long tag value wraps, continuation lines must stay styled as `value` so the
  display can make the wrap visually distinct from the next item.
- Publish deterministic QR review transcript vectors that bind raw QR input to
  the exact displayed frames, physical-style button inputs, terminal decisions,
  and approval-gate state expected from signer review adapters. Screen-mode
  vectors pin the top-level review pages; detail-mode vectors pin
  constrained-display scroll-window behavior without requiring every scroll
  window to be visited before approval.
- Publish deterministic animated QR envelope vectors for larger valid payloads.
  The `nsealr1a:` contract pins decoded JSON digest, one-based frame ordering,
  frame checksums, payload chunk limits, frame-count limits, and response-schema
  validation without adding compression or fountain-code recovery.
- Publish deterministic NIP-46 decrypted payload vectors that bind
  JSON-RPC-like request messages to nSealr request/response payloads or
  non-committal `connect` policy-review intents. Non-`connect` request vectors
  also pin the derived permission requirement and explicit grant/no-grant check
  decisions. Bridge decision vectors pin whether a payload becomes a signer
  request, local `ping` response, `connect` review intent, or deterministic
  permission-denied response, without implying relay, NIP-44, permission grants,
  or auth flows are complete.
- Publish deterministic NIP-46 `connect` review pages for companion and future
  display tests. These pages expose the remote signer pubkey, secret presence,
  and requested permissions, but never echo the secret value and never create an
  authorization, acknowledgement, relay session, NIP-44 session, or persisted
  grant.
- Publish read-only NIP-46 policy-file vectors that pin explicit approved
  permissions consumed by companion decision harnesses without implying grant
  storage, client authorization, `connect` acknowledgement, relay sessions, or
  NIP-44 handling.
- Publish the JSON schema for that read-only policy-file format so independent
  tools can validate the envelope before applying stricter semantic checks such
  as `sign_event` parameter/event-kind equality.
- Publish identity, recovery, policy, and grant descriptor contracts that let
  companion route requests without storing production private-key material.
  These contracts make account descriptors secretless, keep stateless QR vaults
  manual-only, reject QR-vault grants, and require expiry, rate limits,
  revocation, audit, and device policy confirmation for persistent-route
  automation.
- Publish the current account/custody product model for all signer families:
  policies attach to final signing public keys and routes, QR vaults use a
  RAM-only session keyring with SeedSigner-compatible SeedQR import vectors, and
  persistent-device policy authority lives on the device rather than in the
  companion. The current scoped-automation vectors are boundary fixtures, not
  the final user-facing policy menu.
- Publish deterministic policy-decision transcript vectors for persistent-route
  automation boundaries before any grant store or relay session exists. These
  vectors pin valid grant allowance, expired-grant denial, revoked-grant
  denial, decrypt/manual-review routing, export-secret denial, unknown-method
  manual review, and `nsealr-grant-audit-event-v0` output without authorizing
  companion key custody or production policy automation.
- Publish deterministic route-selection vectors that bind an account descriptor
  and requested method to the selected signer route metadata. These vectors are
  secretless routing contracts only: they do not approve a client, create a
  grant, select a transport session, dispatch signer I/O, or claim that the
  selected route is production-ready.
- Publish a deterministic feature conformance matrix for the five first-class
  signer families. The matrix separates final product targets from current
  implementation status and requires the same `contract_id` wherever a feature
  is active on more than one solution. It also keeps Raspberry and ESP32
  stateless QR vault targets in parity while allowing their current hardware
  readiness to differ.
- Publish access-surface contracts when browser extension, local companion
  service, npm SDK, or full NIP-46 relay behavior becomes shared conformance
  behavior. Access surfaces are not signer families; they are adapters above
  companion and must still use shared request validation, policy contracts,
  transport semantics, and signed-output verification.
- Publish one named v0 implementation limit profile for constrained signers.
  These limits bound request size, static QR envelope size, animated QR decoded
  size, animated QR frame payload size/count, serial frame size, NIP-46 message
  size, content size, tag count, tag field size, total tag text, and integer
  safety. They are nSealr safety limits, not Nostr protocol limits. The
  machine-readable source is `vectors/limits/nsealr-v0.json`; the human protocol
  explainer is `protocols/implementation-limits-v0.md`.
- Publish malicious/rejection vectors that define deterministic failure
  behavior before review, approval, response acceptance, or signing. These
  include signed-event response integer and limit checks so hosts cannot accept
  unsafe timestamps, kinds, oversized content, or tag payloads after a device
  signs. Serial-frame vectors also include unsupported frame types so transport
  adapters reject them before JSON is treated as a request or response. They
  live under `vectors/invalid/` and are discovered automatically by the specs
  verifier.
- Keep schemas and examples usable by independent implementations.

## Non-Responsibilities

- No production private key custody.
- No hardware-specific policy.
- No companion UI behavior beyond protocol requirements.
- No browser-extension or npm SDK product behavior unless it is promoted to a
  shared access-surface contract.
- No compatibility path without an explicit route type, validator coverage, and
  ownership. Stale or unowned legacy behavior should be removed or rewritten.

## Design Rule

All signer lines must consume this repository instead of creating divergent
wire formats, event fixtures, or verification rules.
