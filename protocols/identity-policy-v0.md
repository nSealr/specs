# Identity, Recovery, And Policy Contracts v0

NostrSeal v0 separates signer custody from companion routing. These contracts
describe which signer owns an identity, how that identity can be recovered, and
which policy or grant metadata may be stored by the companion or test harnesses.

These files do not authorize companion-side production private-key custody. They
are routing and safety metadata for the five existing signer families.

## Files

- Account descriptors: `vectors/accounts/*.json`
- Policy profiles: `vectors/policies/*.json`
- Grant descriptors: `vectors/grants/*.json`
- Schemas:
  - `schemas/account-descriptor-v0.schema.json`
  - `schemas/policy-profile-v0.schema.json`
  - `schemas/grant-descriptor-v0.schema.json`

## Account Descriptor

`nseal-account-descriptor-v0` binds an `account_id` and public key to an
explicit signer route, recovery metadata, capability metadata, and a policy
profile id.

Allowed route types are:

- `raspberry_qr_vault`
- `esp32_qr_vault`
- `esp32_usb_nip46`
- `smartcard`
- `custom_hardware_wallet`
- `external_nip46`

Account descriptors must not contain `secret_key`, `private_key`, `nsec`,
`mnemonic`, `seed`, `passphrase`, or `nip49_ciphertext` fields. Recovery data
may identify a NIP-06 path, device slot, card slot, or external signer, but it
must not embed the recoverable secret.

Stateless QR vault routes must use:

- `transport: "qr"`
- `custody: "stateless_session"`
- `policy_support: "manual_only"`
- `persistent_grants: false`

They must not reference TROPIC01 or any persistent key-at-rest mechanism.

## Policy Profile

`nseal-policy-profile-v0` describes the policy mode for one or more route
types. `manual_only` means every signing operation needs explicit review and
approval. `scoped_automation` is only allowed for persistent/daily-use signer
routes after expiry, rate-limit, revocation, audit-log, and device-policy
confirmation constraints are present.

QR vault policies must remain `manual_only` with `grants_allowed: false`.

Policy profiles must forbid wildcard grants and secret export. Decrypt,
unknown, relay-switching, delete, and other high-risk methods remain manual
until a later risk model adds stricter source-backed semantics.

## Grant Descriptor

`nseal-grant-descriptor-v0` records one explicit grant for a non-QR route.
Grants must be scoped by account, route, client pubkey, method, and method
parameter when relevant. `sign_event` grants must pin both the string
permission parameter and the integer event kind.

Grant descriptors must include:

- expiry;
- rate limit;
- device policy confirmation;
- revocation support;
- audit event format.

Wildcards are invalid. Stateless QR vault routes are invalid grant targets.

## Change Control

Changing identity, policy, or grant semantics requires updating schemas,
vectors, `scripts/verify_specs.py`, downstream companion validation, and lab
integration. Compatibility paths are allowed only when attached to an explicit
route type and tested; stale or unowned legacy behavior must be removed or
rewritten.
