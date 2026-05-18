# Roadmap

## M1: Specs Foundation

- Signing request v0.
- Signing response v0.
- Common error response.
- Static `nsealr1:` and animated `nsealr1a:` QR envelope v0.
- Serial frame v0.
- Smartcard APDU v0.
- Capability discovery and disabled-signing request/response vectors for
  scaffolded direct devices.
- Trusted review and review-screen vectors for display-oriented approval flows.
- Trusted review detail-page vectors for complete constrained-display review
  pages without changing the approval-digest contract.
- QR review transcript vectors for display/button adapter acceptance tests.
- NIP-46 decrypted payload bridge, `connect` policy-review intent, and
  deterministic `connect` review-page vectors for companion conformance tests.
- NIP-46 permission requirement and permission-check decision vectors for
  explicit policy-matching conformance.
- NIP-46 bridge decision vectors for permitted signer routing, local `ping`,
  `connect` review, and deterministic permission-denied responses.
- NIP-46 read-only policy-file vectors for explicit approved permissions.
- NIP-46 read-only policy-file JSON schema.
- Secretless account-descriptor, policy-profile, and grant-descriptor
  contracts for identity routing, recovery metadata, and scoped automation.
- SeedSigner Standard SeedQR and CompactSeedQR compatibility vectors for
  QR-vault BIP-39 session import into NIP-06 Nostr accounts.
- NIP-19 `nsec` private-key import vectors for direct RAM-only QR vault
  migration/recovery sessions.
- Policy-decision transcript vectors for grant allowance, expired/revoked
  denial, decrypt/manual-review routing, export denial, unknown-method manual
  review, and audit-event output.
- Feature conformance matrix for the five first-class signer families,
  including stateless QR vault parity between Raspberry and ESP32 for review,
  approval, transport, response verification, and RAM-only SeedQR/NIP-19
  `nsec` session import.
- nSealr v0 implementation limit profile for constrained signer safety.
- Malicious/rejection vectors for unsafe signing requests, unsafe responses, QR
  envelopes, serial frames, invalid device request metadata, NIP-46 payloads,
  and policy files.
- JSON schemas.
- Deterministic Nostr/BIP-340 fixtures.

Status: active. The first ESP32-S3 scaffold capability vector,
display-oriented review-screen, QR review transcript, NIP-46 decrypted payload
bridge vectors, NIP-46 `connect` policy-review intent vector, explicit
NIP-46 permission policy vectors, NIP-46 bridge decision vectors, and
read-only NIP-46 policy-file vector/schema are implemented. The v0
implementation limit profile and initial malicious/rejection vectors are now
part of the shared contract. Initial review detail-page vectors are also
implemented for T-Display S3 sized constrained-display conformance.
QR review transcripts now include detail-mode scroll-window navigation so
Raspberry and ESP32 display/button adapter tests can agree on `Next/Scroll`
behavior for long tag reviews.
The `connect` vector now also pins deterministic review pages that show remote
signer identity, secret presence, and requested permissions without producing
an acknowledgement, grant, relay session, or NIP-44 state.

Status note, 2026-05-11: account descriptors, policy profiles, and grant
descriptors now exist as shared vectors and schemas. They keep companion
account metadata secretless, keep Raspberry and ESP32 stateless QR vaults
manual-only, and require scoped grants to carry expiry, rate-limit, revocation,
audit, and device-policy-confirmation constraints.

Status note, 2026-05-11: policy-decision transcript vectors now pin the
pre-storage automation boundary for persistent routes: valid grants may allow a
scoped `sign_event`, expired or revoked grants are denied, decrypt requests
fall back to manual review, secret export is denied, unknown methods require
manual review, and every decision emits a deterministic
`nsealr-grant-audit-event-v0` record.

Status note, 2026-05-11: the identity/policy contract now also records the
official account and custody model. Policies attach to final signing public
keys, not mnemonic containers; BIP-39 passphrases create separate seed
namespaces; QR vaults use RAM-only session keyrings with SeedSigner
SeedQR/CompactSeedQR and NIP-19 `nsec` import as shared vector contracts; and
ESP32/custom persistent devices keep policy authority at the device
authorization boundary. The current scoped-automation fixtures remain minimal
conformance vectors, not the final policy UX.

Status note, 2026-05-13: SeedSigner Standard SeedQR and CompactSeedQR import
is now a shared vector contract rather than a Raspberry-only product note. QR
vault implementations must decode the same BIP-39 session seed material for
NIP-06 Nostr derivation, while Bitcoin descriptors, xpubs, PSBTs, and wallet
policy remain out of scope. Raspberry consumes this vector in the QR vault
flow; ESP32 now consumes it in host-core as a partial QR-vault key-source
parser. ESP32 host-core also validates BIP-39 English mnemonic text and renders
checked word indexes back to mnemonic words, but camera input, NIP-06
derivation, import review screens, response QR output, and real signing remain
pending.

Status note, 2026-05-18: NIP-19 `nsec` private-key import is now a shared
vector contract for RAM-only QR vault migration/recovery sessions. It decodes
to one 32-byte Nostr private key for the current session only and does not
create a persistent key slot, policy record, mnemonic, or NIP-49 backup path.
Raspberry consumes the vector in an end-to-end RAM-only QR vault flow; ESP32
now consumes it in host-core as a partial QR-vault key-source parser, and the
bounded session keyring can hold parsed `nsec` material. Camera input, import
review screens, response QR output, and real signing remain pending.

Status note, 2026-05-18: ESP32 stateless session custody is now partial rather
than merely planned. The host-core owns a bounded RAM-only session keyring model
for already parsed `nsec` and BIP-39 sources, but camera/import UX, device
lifecycle wipe tests, hardware reset behavior, local import review, NIP-06
derivation wiring, response QR output, and real signing remain pending.

Status note, 2026-05-11: the feature conformance matrix is now a shared
contract. It records required, optional, planned, forbidden, and not-applicable
features per first-class signer family, while requiring one canonical behavior
contract for each shared feature. Raspberry and ESP32 stateless QR vault
targets are pinned in parity even though current implementation status can
differ by hardware readiness.

## M3: Transport Contracts

- Capability discovery draft.
- Transport-independent response verification requirements.

## M4.5/M7.5: Pre-Signing Contract Hardening

- Define named nSealr v0 parser and resource limits in one contract.
- Add shared invalid vectors for event-template signed fields, unsafe integer
  values, oversized content/tags/messages, malformed or ambiguous responses,
  malformed QR envelopes, malformed serial frames, invalid device request
  metadata, malformed NIP-46 payloads, and invalid policy files.
- Keep these as nSealr implementation safety limits for constrained
  signers, not Nostr protocol limits.
- Require companion, Raspberry, and ESP32 implementations to consume the
  vectors where their parsers support the relevant boundary before real signing
  or full NIP-46 sessions are enabled.

Status: shared contract and first downstream consumers are implemented. The
specs profile and invalid vectors are part of `nSealr/specs`, companion
validates the shared fixtures and NIP-46 policy-file vectors, Raspberry rejects
applicable unsafe QR/signing requests while preserving RAM-only custody, ESP32
host-core rejects applicable QR/signing/serial hardening vectors before review,
and lab integration now checks live shared fixtures plus sibling snapshot
drift. This gate remains a blocker for ESP32 real signing, browser
extension/full NIP-46 sessions, persistent grants, production smartcard claims,
and custom persistent-secret hardware-wallet claims; any new parser boundary
must add specs vectors before being treated as complete.

Status note, 2026-05-11: invalid response vectors now also cover signed-event
integer safety plus content and tag payloads that exceed the shared v0
implementation limits. Hosts must reject those responses before treating a
device output as accepted signing output. Response `request_id` values now use
the same v0 profile as requests.

Status note, 2026-05-08: invalid serial-frame vectors now include valid
transport frames with invalid decoded request metadata for unsupported
`version` and invalid `request_id` syntax. Device transports must reject these
before request handling or signing paths.

Status note, 2026-05-11: invalid serial-frame vectors now also include an
unsupported frame `type` with a valid checksum. Transports must reject it
before decoded JSON is treated as a request, response, or error payload.

## Later

- Access-surface vectors for local companion service, NIP-07 browser provider,
  npm SDK client behavior, and full NIP-46 relay sessions once those behaviors
  become cross-repository contracts. These remain companion access surfaces,
  not signer families.
- Full encrypted NIP-46 relay/session mapping.
- Firmware conformance vectors.
