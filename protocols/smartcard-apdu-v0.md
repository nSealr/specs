# Smartcard APDU v0

This document defines the first display-less smartcard command boundary for
nSealr experiments.

## Scope

The card signs a 32-byte Nostr event id. It does not parse or review full Nostr
events. Trusted event review must happen in the companion, a QR vault, or another
trusted display surface before sending a digest to a card.

## Command Class

- CLA: `0x80`

## Command Shape

- P1: `0x00`.
- P2: `0x00`.
- Le: omitted.

The v0 profile uses exact short APDUs only. Commands with non-zero P1/P2 or an
explicit Le byte are rejected before any signing operation.

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

## Status Words

- `0x9000`: command accepted.
- `0x6700`: wrong command data length.
- `0x6A86`: incorrect P1/P2 for this APDU profile.
- `0x6D00`: instruction not supported by this APDU profile.
- `0x6E00`: command class not supported by this APDU profile.

## Security Notes

This APDU profile can protect key material, but it cannot provide trusted event
review on its own. A product using this profile must clearly show where event
review happens.
