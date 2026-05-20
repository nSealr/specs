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
  a full Unicode review policy or accepted equivalent exists. It must also keep
  `source_public_key_proof` in `missing_gates` until firmware proves the
  displayed public key is derived from, or otherwise cryptographically bound to,
  the selected key source. Invalid
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
  permissions, but do not echo the secret value. The `connect` fixture also
  pins a digest-bound local approval artifact that records only the reviewed
  digest and explicit no-side-effect flags. Non-`connect` vectors also carry
  the derived permission requirement and positive/negative permission-check
  decisions. All NIP-46 payload vectors also carry explicit
  bridge decisions that pin permitted signer routing, local response routing,
  `connect` review, and permission-denied responses.
- NIP-46 vector discovery tests ensure every `vectors/nip46/*.json` file is
  included in conformance verification.
- NIP-46 policy-file vector discovery tests ensure every
  `vectors/nip46-policy-files/*.json` file is included in conformance
  verification, and each file contains normalized explicit approved
  permissions.
- NIP-46 connection URI vector discovery tests ensure every
  `vectors/nip46-connection-uris/*.json` file is included in conformance
  verification, validates descriptor-only token parsing, and proves expected
  descriptors do not echo shared secret values. Invalid hardening vectors also
  cover malformed connection URI schemes, relays, and missing `nostrconnect`
  secrets.
- NIP-46 session lifecycle vector discovery tests ensure every
  `vectors/nip46-sessions/*.json` file is included in conformance
  verification. The verifier checks reviewed connect-digest binding,
  client/signer pubkeys, normalized unique relays, safe approval/expiry
  integers, approved-permission subsets, absence of secret material, and false
  side-effect flags for NIP-44 derivation, relay I/O, `connect`
  acknowledgement, grant creation, signer dispatch, production secret storage,
  and session persistence.
- NIP-46 session request gate discovery tests ensure every
  `vectors/nip46-session-gates/*.json` file is included in conformance
  verification. The verifier checks source-session binding, sender/client and
  recipient/signer pubkey binding, expiry, permission derivation, and the
  deterministic `connect_ack_pending` rejection before any signer dispatch.
  Invalid gate vectors pin sender mismatch, recipient mismatch, pre-approval
  evaluation, expiry, wrong direction, and `connect` refusal behavior.
- SeedQR vector discovery tests ensure every `vectors/seedqr/*.json` file is
  included in conformance verification.
- NIP-19 `nsec` vector discovery tests ensure every `vectors/nip19/*.json`
  file is included in conformance verification.
- Session import review discovery tests ensure every
  `vectors/session-import-reviews/*.json` file is included in conformance
  verification.
- Source public-key proof discovery tests ensure every
  `vectors/source-public-key-proofs/*.json` file is included in conformance
  verification and that each proof vector derives the expected public key from
  the referenced source material instead of trusting descriptor metadata.
- Session-source backup review discovery tests ensure every
  `vectors/session-source-backups/*.json` file is included in conformance
  verification, that review pages are secret-hidden danger-zone pages, and
  that backup payloads match their source vectors exactly.
- NIP-46 policy-file schema tests ensure
  `schemas/nip46-policy-file-v0.schema.json` declares the required envelope
  fields.
- Account-descriptor, policy-profile, and grant-descriptor discovery tests
  ensure every file under `vectors/accounts/`, `vectors/policies/`, and
  `vectors/grants/` is included in conformance verification.
- Identity/policy semantic tests reject embedded secret fields, QR-vault
  automation, display-less smartcard automation, external NIP-46
  nSealr-managed automation, wildcard grants, route/policy mismatches, missing
  or mismatched NIP-06 recovery source vectors, mismatched NIP-06 recovery
  source fingerprints, and grant targets that point anywhere except ESP32
  USB/NIP-46 or custom hardware-wallet persistent policy routes. They also
  reject
  unsupported descriptor, route, recovery, capability, policy-profile,
  grant-client, grant-permission, and rate-limit fields, malformed
  `policy-*`/`grant-*` identifiers, and inactive `grant_constraints` on
  manual-only profiles. nSealr-managed grant permissions are also pinned to
  the v0 automation menu: only `sign_event` kind `1` may appear in a grant
  descriptor until a later specs revision expands the contract.
- Identity/policy schema tests ensure account descriptors, policy profiles, and
  grant descriptors expose the expected required contract surface, closed
  `additionalProperties: false` boundaries, explicit identifier patterns, and
  no secret-key fields. Account descriptor schema tests also require
  route-type dependent repository, transport, custody, trusted-review,
  policy-support, physical-review, physical-approval, and persistent-grant
  constraints. Policy-profile and grant-descriptor schema tests require nSealr
  scoped grants to stay limited to ESP32 USB/NIP-46 and custom hardware-wallet
  persistent policy routes and to authorize only `sign_event` kind `1` in v0.
  Grant descriptor tests also reject the removed `decision` field so v0 cannot
  grow an ambiguous grant-mode switch outside expiry/rate-limit/revocation
  semantics.
- Policy-profile tests reject unsupported manual-review requirements,
  forbidden-permission names, risk-tier keys, and risk-tier values. This keeps
  the policy profile a closed contract rather than a free-form rule-engine
  escape hatch.
- Policy-change review vector discovery tests ensure every file under
  `vectors/policy-changes/` is included in conformance verification.
- Policy-change review semantic tests pin the persistent-device default
  manual-only policy, deterministic `set_policy` review pages,
  `approval_digest`, required local device review, required physical approval,
  and `companion_authoritative: false` before scoped automation can be treated
  as active policy.
- Policy-decision vector discovery tests ensure every file under
  `vectors/policy-decisions/` is included in conformance verification.
- Policy-decision semantic tests pin allow/deny/manual-review outcomes for
  valid grants, expired grants, revoked grants, active rate-limit windows,
  reset rate-limit windows, route/policy mismatches, decrypt requests, secret
  export requests, and unknown methods before persistent grant storage or relay
  sessions are implemented. Policy-decision requests carry explicit per-grant
  usage snapshots; the shared vectors define decision behavior, not a storage
  backend.
- Route-selection vector discovery tests ensure every file under
  `vectors/route-selections/` is included in conformance verification.
- Route-selection semantic tests pin secretless account-to-route selection for
  supported methods before any persistent grant store, signer transport
  session, or browser/native host dispatch exists. Route-selection schema
  tests also require route-type dependent repository, transport, custody,
  trusted-review, policy-support, physical-review, physical-approval, and
  persistent-grant constraints.
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
  envelope, serial frame, invalid device request metadata, NIP-46 payload,
  policy-file, connection URI, session lifecycle, and session gate vector is
  included in conformance verification.
- Invalid serial-frame vectors cover oversized frames, checksum mismatch,
  malformed payloads, unsupported frame types, and invalid decoded request
  metadata.
- Invalid-vector semantic tests ensure each committed malicious fixture is
  rejected for its expected deterministic reason, rather than merely being
  present in a directory.
- Smartcard APDU vectors preserve command bytes, response bytes, signature
  verification requirements, exact P1/P2/Le command-shape rules, and
  deterministic rejection status words for wrong lengths, unsupported classes,
  unsupported instructions, and profile-shape mismatches.

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
`nsealr-nip46-policy-v0` and normalized explicit approved permissions. Broad
`sign_event` remains valid only as requested-permission metadata; approved
policy-file entries must pin `sign_event` with both `parameter` and
`event_kind`.
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
smartcard policies, manual-only persistent-device defaults, route/policy
membership, and scoped automation constraints for ESP32 USB/NIP-46 and custom
hardware-wallet routes. Policy-change review vectors prove that moving from
manual-only to scoped automation is a digest-bound device review action, not a
companion-side mutation.
It also checks device security-profile vectors so firmware hardening evidence
cannot drift into a production-signing claim before secure boot, flash
encryption, debug locking, provisioning, source public-key proof, and recovery
policy are implemented.
It also checks that policy-decision transcript vectors match the deterministic
pure policy evaluator and emit the expected `nsealr-grant-audit-event-v0`
records for allowed, denied, and manual-review decisions.
It also checks that route-selection vectors match the referenced account
descriptor and supported method, producing secretless route metadata without
authorizing signer I/O, and that route-selection schemas reject impossible
route metadata combinations before external consumers can trust them.
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
`vectors/grants/`, `vectors/policy-changes/`, `vectors/policy-decisions/`,
`vectors/route-selections/`, `vectors/access-surfaces/`, `vectors/features/`,
`vectors/nip46-connection-uris/`, `vectors/nip46-relay-events/`,
`vectors/nip46-relay-steps/`, `vectors/nip46-session-gates/`,
`vectors/seedqr/`, `vectors/nip19/`,
`vectors/session-import-reviews/`, `vectors/source-public-key-proofs/`,
`vectors/session-source-backups/`, and the single profile under `vectors/limits/`
are picked up by tests and
`scripts/verify_specs.py` without hardcoding individual vector filenames in the
verifier.

## Completion Standard

Spec changes are not complete until examples, schemas, fixtures, and docs are
updated together.
