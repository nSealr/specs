# NIP-46 Active Session v0

This contract defines the nSealr active NIP-46 relay session that begins where
`nsealr-nip46-session-lifecycle-v0` (the `approved_pending_ack` checkpoint) ends.

Unlike the checkpoint, this format records an ACTIVE session: connect has been
acknowledged, a NIP-44 conversation key has been derived (in memory), a relay is
open, and session state is persisted. It never persists secret material.

## Phases

| `phase` | Meaning | `opens_relay` | `derives_nip44_key` | `dispatches_signer` |
| --- | --- | --- | --- | --- |
| `connect_ack` | Remote signer acknowledged connect; relay open; NIP-44 derived; not yet dispatching | true | true | false |
| `session_active` | Session live; sign requests may be dispatched | true | true | true |
| `session_closed` | Relay closed; session terminated | false | false | false |

`acknowledges_connect` is true in every phase. `persists_session_state` is true.

## Required Fields

| Field | Rule |
| --- | --- |
| `name` | Stable vector name matching the fixture filename. |
| `format` | Exactly `nsealr-nip46-session-active-v0`. |
| `phase` | One of `connect_ack`, `session_active`, `session_closed`. |
| `client_pubkey` / `remote_signer_pubkey` | Lowercase 32-byte x-only hex. |
| `relays` | Non-empty normalized unique `wss://` relay URL list. |
| `connect_digest` | Lowercase 32-byte digest matching the source checkpoint. |
| `approved_permissions` | Kind-scoped approved permission subset. |
| `nip44` | `{ event_kind: 24133, payload_encrypted: true, version: 2 }`. |
| `persists_session_state` | Exactly `true`. |
| `persisted_state` | `{ fields: [...], contains_secret_material: false }`. |
| `secret_present` | Boolean; records presence only. |

## Required Safety Boundary

- It must not contain secret values, NIP-44 keys, private keys, mnemonics,
  `nsec` values, seeds, or passphrases.
- `secret_value_stored`, `contains_secret_material`, and
  `stores_production_secrets` must be `false`.
- `persisted_state.fields` must not include any secret field name
  (`secret`, `shared_secret`, `session_secret`, `nip44_key`, ...).
- Phase side-effect flags must match the phase table above exactly.

## Source Binding

A fixture wraps the session with `format: nsealr-nip46-session-active-vector-v0`
and `source_session_vector` pointing under `vectors/nip46-sessions/`. The active
session's `client_pubkey`, `remote_signer_pubkey`, `connect_digest`, and `relays`
must match that source `approved_pending_ack` checkpoint, proving continuity.
