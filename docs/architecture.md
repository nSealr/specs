# Architecture

`NostrSeal/specs` is the canonical contract repository for every NostrSeal
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
  explicit `U+XXXX` fallback text for unsupported display glyphs. They are
  display conformance fixtures, not a replacement for the approval-digest
  contract. Their style metadata is part of the contract: if a long tag value
  wraps, continuation lines must stay styled as `value` so the display can make
  the wrap visually distinct from the next item.
- Publish deterministic QR review transcript vectors that bind raw QR input to
  the exact displayed frames, physical-style button inputs, terminal decisions,
  and approval-gate state expected from signer review adapters.
- Publish deterministic animated QR envelope vectors for larger valid payloads.
  The `nseal1a:` contract pins decoded JSON digest, one-based frame ordering,
  frame checksums, payload chunk limits, frame-count limits, and response-schema
  validation without adding compression or fountain-code recovery.
- Publish deterministic NIP-46 decrypted payload vectors that bind
  JSON-RPC-like request messages to NostrSeal request/response payloads or
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
- Publish one named v0 implementation limit profile for constrained signers.
  These limits bound request size, static QR envelope size, animated QR decoded
  size, animated QR frame payload size/count, serial frame size, NIP-46 message
  size, content size, tag count, tag field size, total tag text, and integer
  safety. They are NostrSeal safety limits, not Nostr protocol limits. The
  machine-readable source is `vectors/limits/nseal-v0.json`; the human protocol
  explainer is `protocols/implementation-limits-v0.md`.
- Publish malicious/rejection vectors that define deterministic failure
  behavior before review, approval, response acceptance, or signing. These
  include signed-event response integer and limit checks so hosts cannot accept
  unsafe timestamps, kinds, oversized content, or tag payloads after a device
  signs. They live under
  `vectors/invalid/` and are discovered automatically by the specs verifier.
- Keep schemas and examples usable by independent implementations.

## Non-Responsibilities

- No production private key custody.
- No hardware-specific policy.
- No companion UI behavior beyond protocol requirements.

## Design Rule

All signer lines must consume this repository instead of creating divergent
wire formats, event fixtures, or verification rules.
