# Testing

The specs repository starts with baseline structural verification and will grow
into the conformance suite for all NostrSeal implementations.

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
- NIP-01 event id fixtures match canonical serialization.
- BIP-340 signatures verify against deterministic test keys.
- QR envelope roundtrips preserve the request payload exactly.
- Serial frame vectors preserve the request payload and checksum exactly,
  including valid transport frames whose decoded request metadata must still be
  rejected before device handling.
- Device capability vectors preserve request/response payloads and explicit
  safety flags.
- Device scaffold rejection vectors prove disabled signing returns a protocol
  error instead of a transport error.
- Trusted review vectors preserve event kind, content preview, tag summary, and
  warning semantics for display-oriented signers.
- Review vector discovery tests ensure every `vectors/review/*.json` file is
  included in conformance verification instead of relying on a fixed list.
- Review-screen vectors preserve rendered page order, final approve/reject
  action, and request-bound approval digests.
- Review-screen vector discovery tests ensure every
  `vectors/review-screens/*.json` file is included in conformance verification.
- Review display-frame vectors preserve display limits, page selection, bounded
  title/body/action output, and long-body wrapping/truncation behavior.
- Review display-frame vector discovery tests ensure every
  `vectors/review-display-frames/*.json` file is included in conformance
  verification.
- QR review transcript vectors preserve the raw QR envelope, source request,
  approval digest, displayed frame before each physical-style input, terminal
  decision, and approval-gate state.
- QR review transcript discovery tests ensure every
  `vectors/review-transcripts/*.json` file is included in conformance
  verification.
- NIP-46 decrypted payload vectors preserve `get_public_key`, `sign_event`, and
  local `ping` mapping between NIP-46 JSON-RPC-like messages and NostrSeal
  request/response payloads, plus `connect` parsing into policy-review intents
  without `ack` or permission grants. Non-`connect` vectors also carry the
  derived permission requirement and positive/negative permission-check
  decisions. All NIP-46 payload vectors also carry explicit bridge decisions
  that pin permitted signer routing, local response routing, `connect` review,
  and permission-denied responses.
- NIP-46 vector discovery tests ensure every `vectors/nip46/*.json` file is
  included in conformance verification.
- NIP-46 policy-file vector discovery tests ensure every
  `vectors/nip46-policy-files/*.json` file is included in conformance
  verification, and each file contains normalized explicit approved
  permissions.
- NIP-46 policy-file schema tests ensure
  `schemas/nip46-policy-file-v0.schema.json` declares the required envelope
  fields.
- Implementation-limit tests ensure the v0 limit profile is named, documented,
  and consumed by invalid-vector verification.
- Invalid-vector discovery tests ensure every malicious request, QR envelope,
  serial frame, invalid device request metadata, NIP-46 payload, and
  policy-file vector is included in conformance verification.
- Invalid-vector semantic tests ensure each committed malicious fixture is
  rejected for its expected deterministic reason, rather than merely being
  present in a directory.
- Smartcard APDU vectors preserve command bytes, response bytes, and signature
  verification requirements.

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
It also checks that every review-transcript vector matches the deterministic
frame/button/decision sequence expected from QR signer review adapters.
It also checks that every NIP-46 decrypted payload vector maps to the expected
NostrSeal request, local response, signer response payload, or `connect`
policy-review intent, and that every non-`connect` NIP-46 vector has matching
permission requirements, permission-check decisions, and bridge decisions.
It also checks that every NIP-46 policy-file vector uses
`nseal-nip46-policy-v0` and normalized explicit approved permissions.
It also checks the shared pre-signing hardening vectors so downstream
implementations get deterministic rejection fixtures before enabling real
signing or full NIP-46 sessions.
Those checks are directory-driven: new files under `vectors/invalid/` and the
single profile under `vectors/limits/` are picked up by tests and
`scripts/verify_specs.py` without hardcoding individual vector filenames in the
verifier.

## Completion Standard

Spec changes are not complete until examples, schemas, fixtures, and docs are
updated together.
