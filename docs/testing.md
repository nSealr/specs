# Testing

The specs repository starts with baseline structural verification and will grow
into the conformance suite for all nSealr implementations.

## Current Baseline

```sh
make ci
```

The baseline check verifies required files, directory layout, README license
section, CI workflow, license marker, schemas, examples, and cryptographic
fixtures.

## Required M1 Tests

- JSON schemas validate all valid examples.
- Invalid examples fail for the expected reason.
- NIP-06 mnemonic derivation vectors preserve canonical source metadata, path,
  account, secret key, and public key.
- SeedSigner Standard SeedQR and CompactSeedQR vectors preserve deterministic
  BIP-39 seed-material import for NIP-06 Nostr derivation. The verifier checks
  four-digit word indexes, BIP-39 index bounds, and CompactSeedQR entropy bytes
  derived from the same indexes after checksum-bit removal.
- NIP-19 `nsec` vectors preserve deterministic direct private-key import for
  RAM-only QR vault sessions. The verifier checks lowercase Bech32 checksum,
  `nsec` prefix, 32-byte payload, x-only public key derivation, and scope text
  that excludes persistent policy/key-slot semantics.
- Session import review vectors preserve deterministic, secret-hidden local
  review for RAM-only SeedQR/BIP-39 and NIP-19 `nsec` QR vault session
  sources. The verifier checks source-vector binding, source fingerprint,
  `review_id`, import `approval_digest`, two-page review shape, `Secret:
  hidden` wording, and absence of mnemonic words, `nsec`, or raw private-key
  bytes. These vectors do not derive NIP-06 keys, persist source material, or
  approve signing.
- NIP-01 event id fixtures match canonical serialization.
- BIP-340 signatures verify against deterministic test keys.
- QR envelope roundtrips preserve the request payload exactly,
  implementations must reject encode-side static QR payloads that would exceed
  the same decoded JSON byte limit enforced by decoders, and animated QR frame
  vectors must reassemble with deterministic digest, checksum, ordering, and
  response-schema validation.
- Serial frame vectors preserve the request payload and checksum exactly,
  including valid transport frames whose decoded request metadata must still be
  rejected before device handling.
- Device capability vectors preserve request/response payloads and explicit
  safety flags.
- Device scaffold rejection vectors prove disabled signing returns a protocol
  error instead of a transport error.
- Signing-status vectors preserve both `missing_gates` and
  `development_accepted_gates` so device diagnostics can report development
  evidence without turning it into a production signing claim. The ESP32-S3
  scaffold vector must keep `unicode_review_rendering` in `missing_gates` until
  a full Unicode review policy or accepted equivalent exists, and invalid
  signing-status vectors reject contradictory `signing_enabled: true` responses
  that still report missing gates plus disabled responses that omit the reason
  for disabled signing. Gate lists must also remain duplicate-free.
- Device security-profile vectors preserve the ESP32 USB/NIP-46 development
  hardening boundary: signing disabled, secure boot/flash encryption/debug lock
  not enabled, persistent-secret storage not implemented, required profile
  sections present, and production blockers still explicit.
- Trusted review vectors preserve raw event kind, created_at, signer author
  pubkey, complete content, complete structured tags, and final decision
  semantics for display-oriented signers. They do not encode inferred kind
  labels, abbreviated tag summaries, or heuristic warning pages.
- Review vector discovery tests ensure every `vectors/review/*.json` file is
  included in conformance verification instead of relying on a fixed list.
- Review-screen vectors preserve rendered page order, final approve/reject
  action, and request-bound approval digests.
- Review-screen vector discovery tests ensure every
  `vectors/review-screens/*.json` file is included in conformance verification.
- Review display-frame vectors preserve display limits, page selection, bounded
  title/body/action output, long-body wrapping/truncation behavior, and UTF-8
  codepoint-boundary preservation.
- Review display-frame vector discovery tests ensure every
  `vectors/review-display-frames/*.json` file is included in conformance
  verification.
- Review detail-page vectors preserve complete physical Event/Content/Tags/
  Decision pages for constrained displays, including scroll-window indicators,
  compact body-line styles, long tag continuation indentation, visible
  JSON-style escapes for decoded control characters, and explicit codepoint
  fallback for unsupported glyphs.
- Review detail-page semantic tests reject drift where `body_line_styles` no
  longer line up with rendered lines, use unknown style names, or mark
  continuation lines as anything other than `value`.
- Review detail-page vector discovery tests ensure every
  `vectors/review-detail-pages/*.json` file is included in conformance
  verification.
- QR review transcript vectors preserve the raw QR envelope, source request,
  approval digest, displayed frame before each physical-style input, terminal
  decision, and approval-gate state. Detail-mode transcript vectors also pin
  `scroll` inputs within constrained-display Content or Tags windows.
- QR review transcript discovery tests ensure every
  `vectors/review-transcripts/*.json` file is included in conformance
  verification.
- NIP-46 decrypted payload vectors preserve `get_public_key`, `sign_event`, and
  local `ping` mapping between NIP-46 JSON-RPC-like messages and nSealr
  request/response payloads, plus `connect` parsing into policy-review intents
  and deterministic review pages without `ack` or permission grants. The
  review pages show the remote signer pubkey, secret presence, and requested
  permissions, but do not echo the secret value. Non-`connect` vectors also
  carry the derived permission requirement and positive/negative
  permission-check decisions. All NIP-46 payload vectors also carry explicit
  bridge decisions that pin permitted signer routing, local response routing,
  `connect` review, and permission-denied responses.
- NIP-46 vector discovery tests ensure every `vectors/nip46/*.json` file is
  included in conformance verification.
- NIP-46 policy-file vector discovery tests ensure every
  `vectors/nip46-policy-files/*.json` file is included in conformance
  verification, and each file contains normalized explicit approved
  permissions.
- SeedQR vector discovery tests ensure every `vectors/seedqr/*.json` file is
  included in conformance verification.
- NIP-19 `nsec` vector discovery tests ensure every `vectors/nip19/*.json`
  file is included in conformance verification.
- Session import review discovery tests ensure every
  `vectors/session-import-reviews/*.json` file is included in conformance
  verification.
- NIP-46 policy-file schema tests ensure
  `schemas/nip46-policy-file-v0.schema.json` declares the required envelope
  fields.
- Account-descriptor, policy-profile, and grant-descriptor discovery tests
  ensure every file under `vectors/accounts/`, `vectors/policies/`, and
  `vectors/grants/` is included in conformance verification.
- Identity/policy semantic tests reject embedded secret fields, QR-vault
  automation, display-less smartcard automation, wildcard grants, route/policy
  mismatches, and grant targets that point at stateless QR vault routes.
- Identity/policy schema tests ensure account descriptors, policy profiles, and
  grant descriptors expose the expected required contract surface without
  adding secret-key fields.
- Policy-decision vector discovery tests ensure every file under
  `vectors/policy-decisions/` is included in conformance verification.
- Policy-decision semantic tests pin allow/deny/manual-review outcomes for
  valid grants, expired grants, revoked grants, decrypt requests, secret export
  requests, and unknown methods before persistent grant storage or relay
  sessions are implemented.
- Route-selection vector discovery tests ensure every file under
  `vectors/route-selections/` is included in conformance verification.
- Route-selection semantic tests pin secretless account-to-route selection for
  supported methods before any persistent grant store, signer transport
  session, or browser/native host dispatch exists.
- Access-surface vector discovery tests ensure every file under
  `vectors/access-surfaces/` is included in conformance verification.
- Access-surface semantic tests pin secretless browser/local-service behavior:
  the selected route public key is returned through authorized route selection,
  `signEvent` without a configured signer dispatcher becomes a deterministic
  non-retryable protocol error, and the browser surface cannot contain secret
  fields or claim browser-side production key custody.
- Feature-matrix discovery tests ensure every file under `vectors/features/`
  is included in conformance verification.
- Feature-matrix semantic tests reject shared feature contract drift, unknown
  signer families, unknown features, missing notes, inactive features that
  still claim a contract, and Raspberry/ESP32 stateless QR vault target drift,
  including SeedQR/CompactSeedQR import, NIP-19 `nsec` import, and local
  RAM-only source-generation parity.
- Implementation-limit tests ensure the v0 limit profile is named, documented,
  and consumed by invalid-vector verification.
- Invalid-vector discovery tests ensure every malicious request, response, QR
  envelope, serial frame, invalid device request metadata, NIP-46 payload, and
  policy-file vector is included in conformance verification.
- Invalid serial-frame vectors cover oversized frames, checksum mismatch,
  malformed payloads, unsupported frame types, and invalid decoded request
  metadata.
- Invalid-vector semantic tests ensure each committed malicious fixture is
  rejected for its expected deterministic reason, rather than merely being
  present in a directory.
- Smartcard APDU vectors preserve command bytes, response bytes, signature
  verification requirements, and deterministic rejection status words for wrong
  lengths, unsupported classes, and unsupported instructions.

## Fixture Verification

`scripts/verify_specs.py` computes NIP-01 event ids from canonical serialized
events and verifies committed BIP-340 signatures using libsecp256k1 bindings.
It also checks that invalid request examples remain rejected and that committed
transport vectors match the QR and serial framing rules.
It also checks that every review vector file matches the deterministic review
model used by Raspberry QR vault, companion, and future display firmware tests.
It also checks that every review-screen vector matches the deterministic page
model and approval-digest calculation used by signer approval flows.
It also checks that every review display-frame vector matches deterministic
bounded rendering for the selected source review page and display limits.
It also checks that every review detail-page vector matches deterministic
complete physical review pages while keeping the `screen-pages`
`approval_digest` unchanged.
It also checks detail-page body-line style integrity so wrapped tag or author
values remain visually distinguishable from new items on constrained screens.
It also checks that every review-transcript vector matches the deterministic
frame/button/decision sequence expected from QR signer review adapters,
including detail-mode scroll-window navigation.
It also checks that every NIP-46 decrypted payload vector maps to the expected
nSealr request, local response, signer response payload, or `connect`
policy-review intent and review pages, and that every non-`connect` NIP-46
vector has matching permission requirements, permission-check decisions, and
bridge decisions.
It also checks that every NIP-46 policy-file vector uses
`nsealr-nip46-policy-v0` and normalized explicit approved permissions.
It also checks SeedSigner-compatible SeedQR vectors so Standard SeedQR digits
and CompactSeedQR entropy bytes stay bound to the same BIP-39 word indexes.
It also checks NIP-19 `nsec` vectors so direct private-key import stays
lowercase Bech32/checksum validated and scoped to RAM-only migration/recovery
sessions.
It also checks session import review vectors so parsed QR vault key sources get
the same secret-hidden review pages, source fingerprints, `review_id`, and
import approval digests across Raspberry and ESP32 implementations before any
local load action.
It also checks that account, policy, and grant descriptor vectors preserve the
secretless companion boundary, manual-only QR-vault and display-less
smartcard policies, route/policy membership, and scoped automation constraints
for ESP32 USB/NIP-46 and custom hardware-wallet routes.
It also checks device security-profile vectors so firmware hardening evidence
cannot drift into a production-signing claim before secure boot, flash
encryption, debug locking, provisioning, and recovery policy are implemented.
It also checks that policy-decision transcript vectors match the deterministic
pure policy evaluator and emit the expected `nsealr-grant-audit-event-v0`
records for allowed, denied, and manual-review decisions.
It also checks that route-selection vectors match the referenced account
descriptor and supported method, producing secretless route metadata without
authorizing signer I/O.
It also checks that access-surface vectors stay secretless and deterministic,
including NIP-07 browser provider behavior over local companion service route
selection and signer-unavailable dispatch.
It also checks the feature conformance matrix so each active shared feature
uses the same canonical `contract_id`, every first-class signer family reports
the same feature set, and Raspberry/ESP32 stateless QR vault targets remain in
parity while current status can differ.
It also checks the shared pre-signing hardening vectors, including strict
response-shape rejection for ambiguous success results, error/result mixing,
unknown top-level response fields, malformed response request ids,
signed-event response integer-safety and content/tag limit violations, and
contradictory signing-status readiness, reason-less disabled status, and
duplicate signing-status gate entries, so downstream
implementations get deterministic rejection fixtures before enabling real
signing or full NIP-46 sessions.
Those checks are directory-driven: new files under `vectors/invalid/`,
`vectors/review-detail-pages/`, `vectors/accounts/`, `vectors/policies/`,
`vectors/grants/`, `vectors/policy-decisions/`, `vectors/route-selections/`,
`vectors/access-surfaces/`, `vectors/features/`, `vectors/seedqr/`,
`vectors/nip19/`, `vectors/session-import-reviews/`, and the single profile under
`vectors/limits/` are picked up by tests and
`scripts/verify_specs.py` without hardcoding individual vector filenames in the
verifier.

## Completion Standard

Spec changes are not complete until examples, schemas, fixtures, and docs are
updated together.
