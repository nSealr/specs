# Architecture

`NostrSeal/specs` is the canonical contract repository for every NostrSeal
signer implementation.

## Responsibilities

- Define signing request and response formats.
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
  for small trusted screens.
- Publish deterministic QR review transcript vectors that bind raw QR input to
  the exact displayed frames, physical-style button inputs, terminal decisions,
  and approval-gate state expected from signer review adapters.
- Publish deterministic NIP-46 decrypted payload vectors that bind
  JSON-RPC-like request messages to NostrSeal request/response payloads without
  implying relay, NIP-44, or permission handling is complete.
- Keep schemas and examples usable by independent implementations.

## Non-Responsibilities

- No production private key custody.
- No hardware-specific policy.
- No companion UI behavior beyond protocol requirements.

## Design Rule

All signer lines must consume this repository instead of creating divergent
wire formats, event fixtures, or verification rules.
