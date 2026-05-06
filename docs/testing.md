# Testing

The specs repository starts with baseline structural verification and will grow
into the conformance suite for all NostrSeal implementations.

## Current Baseline

```sh
make ci
```

The baseline check verifies required files, directory layout, README license
section, CI workflow, and license marker.

## Required M1 Tests

- JSON schemas validate all valid examples.
- Invalid examples fail for the expected reason.
- NIP-01 event id fixtures match canonical serialization.
- BIP-340 signatures verify against deterministic test keys.
- QR envelope roundtrips preserve the request payload exactly.

## Completion Standard

Spec changes are not complete until examples, schemas, fixtures, and docs are
updated together.

