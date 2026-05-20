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
- NIP-46 connection URI vectors for descriptor-only `bunker://` and
  `nostrconnect://` token parsing.
- NIP-46 session lifecycle checkpoint vectors for reviewed-but-not-active
  `connect` state, without NIP-44 key derivation, relay I/O, acknowledgement,
  grants, signer dispatch, production secret storage, or persistence.
- NIP-46 read-only policy-file JSON schema.
- Secretless account-descriptor, policy-profile, and grant-descriptor
  contracts for identity routing, recovery metadata, and scoped automation.
- Persistent-device manual-only default policy plus policy-change review
  vectors for digest-bound `set_policy` proposals.
- SeedSigner Standard SeedQR and CompactSeedQR compatibility vectors for
  QR-vault BIP-39 session import into NIP-06 Nostr accounts.
- NIP-19 `nsec` private-key import vectors for direct RAM-only QR vault
  migration/recovery sessions.
- Policy-decision transcript vectors for grant allowance, expired/revoked
  denial, rate-limit denial, rate-window reset allowance, route/policy
  mismatch manual review, decrypt/manual-review routing, export denial,
  unknown-method manual review, and audit-event output.
- Access-surface vector for the NIP-07 browser provider over the local
  companion service, binding authorized route selection, deterministic
  signer-unavailable behavior, and the secretless browser boundary.
- Route-refusal contract vector for local companion dispatch across all route
  selections, binding no-dispatcher refusal, display-less smartcard
  external-review acknowledgement requirements, trusted-review acknowledgement
  rejection, and the no-secret/no-grant/no-dispatch safety boundary.
- Feature conformance matrix for the five first-class signer families,
  including stateless QR vault parity between Raspberry and ESP32 for review,
  approval, transport, response verification, and RAM-only SeedQR/NIP-19
  `nsec` session import plus local RAM-only source generation.
- Firmware boot-hardening profile vector for the ESP32 USB/NIP-46 development
  scaffold, covering the validated development-only security profile and
  read-only eFuse audit boundary without enabling irreversible hardening or
  production signing.
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
signer identity, secret presence, and requested permissions, plus a
digest-bound local approval artifact for the reviewed pages, without producing
an acknowledgement, grant, relay session, or NIP-44 state.
NIP-46 connection URI vectors now pin descriptor-only parsing of `bunker://`
and `nostrconnect://` tokens, including relay validation, requested
permissions, optional client metadata, and proof that parsed descriptors never
echo shared secret values.
NIP-46 relay event envelope vectors now pin the first M5 relay-session boundary:
`kind:24133` events must expose a valid sender pubkey, exactly one recipient
`p` tag, and opaque encrypted content before any relay I/O, NIP-44 decryption,
grant creation, or signer dispatch is implemented.
NIP-46 relay step vectors now pin the next M5 boundaries: once a plaintext
message has been supplied by a future decryption layer, request steps must
return the same bridge decision they would return for local decrypted payloads,
and response steps must shape-check plaintext NIP-46 response messages while
binding public-key and signed-event result pubkeys to the relay-event sender.
Auth challenge responses are now recognized as metadata-only response steps:
they expose a safe http(s) auth URL without credentials or fragments for later
UI, without opening it or treating a generic result/error pair as valid. Both
still avoid relay I/O, NIP-44 decryption, `connect` acknowledgement, grant
creation, signer dispatch, signature verification, and session persistence.
NIP-46 auth challenge review vectors now pin the next manual boundary after
that response metadata: companion can render deterministic review pages for the
remote signer, client pubkey, and auth URL, then write a digest-bound local
approval artifact only when the reviewed auth challenge digest is supplied
back. This still does not open the URL, acknowledge `connect`, open relays,
create grants, dispatch signers, store production secrets, or persist session
state.
NIP-46 session lifecycle checkpoint vectors now pin the next M5 boundary after
manual connect approval: a reviewed digest, client/signer pubkeys, relays,
approval time, expiry, requested permissions, and approved permission subsets
can be represented without storing secret material, deriving NIP-44 keys,
acknowledging `connect`, opening relays, creating grants, dispatching signers,
storing production secrets, or persisting session state.
NIP-46 pending-session request gate vectors now pin the next non-enabling M5
boundary: a decrypted request can be checked against the reviewed
`approved_pending_ack` checkpoint and relay envelope, but it must still be
rejected with `connect_ack_pending` and must not use session permissions,
acknowledge `connect`, open relays, create grants, dispatch signers, store
production secrets, or persist session state. Invalid gate vectors now also
pin sender mismatch, recipient mismatch, pre-approval evaluation, expiry, wrong
direction, and `connect` refusal.

Status note, 2026-05-11: account descriptors, policy profiles, and grant
descriptors now exist as shared vectors and schemas. They keep companion
account metadata secretless, keep Raspberry and ESP32 stateless QR vaults
manual-only, keep display-less smartcard routes manual-only with external
review acknowledgement, and require scoped grants to carry expiry, rate-limit,
revocation, audit, and device-policy-confirmation constraints for ESP32
USB/NIP-46 and custom hardware-wallet routes.
Status note, 2026-05-19: the verifier now mirrors the closed-schema JSON
contracts for routing and policy descriptors, including nested signer routes,
recovery records, capabilities, grant clients, grant permissions, rate limits,
and strict `policy-*` / `grant-*` identifiers.

Status note, 2026-05-19: nSealr-managed grant descriptors now pin the v0
automation menu to `sign_event` kind `1` only. Other event kinds and other
methods remain manual-review or future-spec work until a later specs revision
adds explicit vectors, schema, and downstream parser support.

Status note, 2026-05-20: the v0 grant descriptor no longer carries a separate
grant decision mode. Temporary automation is expressed through the same scoped
session grant with `expires_at`, `rate_limit`, revocation, audit, and
device-policy confirmation; one-use behavior is modeled as a grant with
`rate_limit.max_uses` set to `1`.

Status note, 2026-05-20: policy-profile vocabulary is now closed. Manual-review
requirements, forbidden permissions, and risk-tier names/values must use the
small v0 enum set in the shared schema and verifier, so new policy knobs cannot
be accepted as arbitrary metadata.

Status note, 2026-05-19: policy-decision transcript vectors now pin the
pre-storage automation boundary for persistent routes: valid grants may allow a
scoped `sign_event`, expired or revoked grants are denied, active rate-limit
windows are denied, reset rate-limit windows allow the next request,
route/policy mismatches fall back to manual review, decrypt requests fall back
to manual review, secret export is denied, unknown methods require manual
review, and every decision emits a deterministic
`nsealr-grant-audit-event-v0` record. The vectors carry explicit per-grant
usage snapshots but do not add a persistent grant store.

Status note, 2026-05-11: the identity/policy contract now also records the
official account and custody model. Policies attach to final signing public
keys, not mnemonic containers; BIP-39 passphrases create separate seed
namespaces; QR vaults use RAM-only session keyrings with SeedSigner
SeedQR/CompactSeedQR and NIP-19 `nsec` import as shared vector contracts; and
ESP32/custom persistent devices keep policy authority at the device
authorization boundary. Persistent-device account descriptors now default to
manual-only policy, while the scoped-automation fixtures remain minimal
conformance vectors that require a separate device-reviewed policy-change
proposal before they can be active policy.

Status note, 2026-05-20: `persistent-secret-custody-v0` is now a standalone
machine-readable custody contract under `vectors/custody/` with a matching
human protocol explainer. It keeps the custom hardware wallet in research
status while pinning no-plaintext-at-rest, wrapped/encrypted storage,
TROPIC01-assisted ESP32-S3 RAM unlock, wipe events, MAC-and-Destroy PIN
hardening, and backup/export review gates.

Status note, 2026-05-19: NIP-06 account descriptors now require their
`recovery.source_vector` to exist, match the descriptor public key, and expose
a `recovery.source_fingerprint` matching the same RAM-only import-review
fingerprint used by QR vault session-source review. The ESP32 QR account
descriptor was aligned with the same canonical NIP-06 account 0 vector used by
the Raspberry QR vault, preserving route separation while removing a stale
missing-source reference.

Status note, 2026-05-19: policy-change review vectors now pin the pre-storage
policy mutation boundary. A secretless companion/browser/SDK proposal may
request `set_policy`, but the reviewed pages and `approval_digest` explicitly
require local device review and physical approval; the companion is never the
authoritative policy mutator.

Status note, 2026-05-19: Raspberry's package-owned session keyring now keeps
mutable internal copies of imported QR-vault sources and wipes those slots on
`clear()` and destruction as best-effort Python process hygiene. This does not
claim interpreter-wide secure memory erasure; real Pi power-cycle/session-loss
evidence remains a hardware acceptance blocker.

Status note, 2026-05-19: Raspberry now also has a package-owned decoded
session-source QR boundary matching the ESP32 host-core shape. It classifies
decoded text as canonical NIP-19 `nsec`, SeedSigner Standard SeedQR, or plain
BIP-39 mnemonic text, handles CompactSeedQR entropy bytes on the byte-input
path, and composes those sources with the shared secret-hidden import-review
gate before RAM-only keyring load. Real Pi camera/display/button import UX
remains pending.

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

Status note, 2026-05-19: local session-source generation is now a shared
feature contract for stateless QR vault targets. Raspberry owns the first
package-level boundary for generated 12- or 24-word BIP-39 sources and
standalone `nsec`-equivalent private-key sources in RAM with deterministic
entropy injection for tests. ESP32 host-core now has the matching generation
boundary for explicit entropy inputs. The shared specs now also include
danger-zone backup review vectors for BIP-39 words/SeedQR and NIP-19 `nsec`
payload reveal, so implementations can test explicit physical approval before
generated material is shown for recovery. Hardware RNG wiring, physical backup
display/output acceptance, hardware review acceptance, and lifecycle-loss
evidence remain pending.

Status note, 2026-05-19: ESP32 host-core now consumes the shared signed
response QR envelope vector in the encode direction. It can turn already
produced response JSON into static `nsealr1:` and animated `nsealr1a:` output,
but real signing, display hardware, scan-back, and hardware acceptance remain
pending.

Status note, 2026-05-19: ESP32 USB/NIP-46 secure-boot hardening is now partial
in Feature Conformance v0. `vectors/devices/esp32-s3-security-profile-development.json`
pins the development-only profile boundary: runtime and production signing
disabled, secure boot and flash encryption off, debug access unlocked for
bring-up, persistent-secret storage not implemented, production blockers
present, source public-key proof still missing, and only a read-only eFuse audit
path available.

Status note, 2026-05-18: ESP32 stateless session custody is now partial rather
than merely planned. The host-core owns a bounded RAM-only session keyring model
for already parsed `nsec` and BIP-39 sources, but camera/import UX, device
lifecycle hardware acceptance, hardware reset behavior, local import review,
NIP-06 derivation wiring, response QR output, and real signing remain pending.

Status note, 2026-05-19: the ESP32 host-core keyring now wipes active source
slots on `clear()` and destruction and disables copy/move operations so
RAM-only QR-vault key material is not duplicated by ordinary ownership
changes. Hardware reset behavior and physical lifecycle acceptance remain
pending.

Status note, 2026-05-19: ESP32 `SessionKeySource` temporaries now wipe
sensitive arrays on destruction, assignment replacement, and move-source
cleanup. Decoded QR session-source inputs also compose with the local
import-review button flow before RAM-only keyring load, so host-core tests prove
`nsec`, Standard SeedQR, and CompactSeedQR inputs cannot bypass final-page
import approval. Camera input, NIP-06 derivation, response QR output, hardware
acceptance, and real signing remain pending.

Status note, 2026-05-18: ESP32 host-core now also builds secret-hidden import
review summaries for parsed `nsec` and BIP-39 sources. The summary exposes
type, label, word count when applicable, and a deterministic fingerprint while
hiding raw `nsec` bytes and mnemonic words. Hardware display/button acceptance,
camera/import UX, NIP-06 derivation, response QR output, and real signing
remain pending.

Status note, 2026-05-19: ESP32 host-core now also normalizes decoded session
source QR inputs into the same RAM-only `SessionKeySource` boundary. This
covers canonical NIP-19 `nsec` text, plain BIP-39 English mnemonic QR text,
SeedSigner Standard SeedQR digit streams, and CompactSeedQR entropy bytes.
Physical camera capture, NIP-06 derivation, public-key derivation proof,
persistence, response QR display hardware, and real signing remain pending.

Status note, 2026-05-19: ESP32 host-core now validates secretless QR
session-account metadata against the RAM-only session keyring, including the
reviewed source fingerprint, and can pass the selected public key into QR
review flow identity. This updates the Feature Conformance v0 notes for
`approval_digest_binding` and `stateless_session_custody` without adding a new
feature or claiming NIP-06 derivation, persistence, or signing.

Status note, 2026-05-19: `vectors/source-public-key-proofs/` now defines the
shared source-to-public-key proof contract for NIP-06 BIP-39 sources and
NIP-19 `nsec` sources. This supports the `source_public_key_proof` signing gate:
implementations must derive or otherwise prove the displayed public key from the
selected RAM-only source before real signing, instead of trusting only account
descriptors or reviewed source fingerprints.

Status note, 2026-05-11: the feature conformance matrix is now a shared
contract. It records required, optional, planned, forbidden, and not-applicable
features per first-class signer family, while requiring one canonical behavior
contract for each shared feature. Raspberry and ESP32 stateless QR vault
targets are pinned in parity even though current implementation status can
differ by hardware readiness.

Status note, 2026-05-19: the first access-surface vector is now part of the
shared contract. It covers `@nsealr/browser-provider` using the local
companion service for route selection: `getPublicKey` returns the selected
ESP32 USB route public key, while `signEvent` without an explicit signer
dispatcher returns a deterministic `signer_route_unavailable` response. This
does not add a signer family, browser key custody, persistent grants, relay
sessions, or production signing.

## M3: Transport Contracts

- Capability discovery draft.
- Transport-independent response verification requirements.

## M4.5/M7.5: Pre-Signing Contract Hardening

- Define named nSealr v0 parser and resource limits in one contract.
- Add shared invalid vectors for event-template signed fields, unsafe integer
  values, oversized content/tags/messages, malformed or ambiguous responses,
  malformed QR envelopes, malformed serial frames, invalid device request
  metadata, malformed NIP-46 payloads, invalid policy files, and malformed
  NIP-46 connection URIs.
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
The same rule now applies to pending NIP-46 session gates: request dispatch
from an approved-but-unacknowledged session remains blocked until a later specs
contract introduces acknowledged sessions, NIP-44 handling, and grant review.

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

- Additional access-surface vectors for npm SDK client behavior and full
  NIP-46 relay sessions once those behaviors become cross-repository
  contracts. These remain companion access surfaces, not signer families.
- Full encrypted NIP-46 relay/session mapping.
- Firmware conformance vectors.
