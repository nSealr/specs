# Smartcard APDU v0

This document defines the first display-less smartcard command boundary for
NostrSeal experiments.

## Scope

The card signs a 32-byte Nostr event id. It does not parse or review full Nostr
events. Trusted event review must happen in the companion, a QR vault, or another
trusted display surface before sending a digest to a card.

## Command Class

- CLA: `0x80`

## Instructions

### `GET_PUBLIC_KEY`

- INS: `0x10`
- Data: empty.
- Response data: 32-byte x-only secp256k1 public key.
- Success status word: `0x9000`.

### `SIGN_EVENT_ID`

- INS: `0x20`
- Data: exactly 32 bytes containing the Nostr event id.
- Response data: 64-byte BIP-340 Schnorr signature.
- Success status word: `0x9000`.

## Security Notes

This APDU profile can protect key material, but it cannot provide trusted event
review on its own. A product using this profile must clearly show where event
review happens.
