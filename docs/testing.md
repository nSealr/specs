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
- Serial frame vectors preserve the request payload and checksum exactly.
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

## Completion Standard

Spec changes are not complete until examples, schemas, fixtures, and docs are
updated together.
