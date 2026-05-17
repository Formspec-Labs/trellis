# Derivation — `append/037-user-content-attestation-multi-attestor`

ADR 0010 §"Wire shape" positive vector for `trellis.user-content-attestation.v1`.

## Inputs

- Issuer key: `_keys/issuer-001.cose_key` (Ed25519 / suite-id 1).
- `attestation_id` = `urn:trellis:user-content-attestation:test:037-applicant`
- `attested_event_hash` = `7b3d738cefc69529716bb12ee7a363f8b622c8c60a0f950d51a2223ccc2d71f4` (deterministic
  fixture marker: `SHA-256("trellis-fixture-host-event:037")`).
- `attested_event_position` = `0`
- `attestor` = `urn:trellis:principal:applicant-037`
- `identity_attestation_ref` = `a1525dd4c3679ae2759ef5db8cd84a4cf75d47eb2b1bb9be6cc58741b51924fa` (32 bytes)
- `signing_intent` = `urn:wos:signature-intent:applicant-affirmation` (RFC 3986 syntactically valid;
  semantics owned by WOS Signature Profile per ADR 0010 §"Field semantics").
- `attested_at` = `[1776900000, 0]` (= envelope `authored_at`; ADR 0010
  §"Verifier obligations" step 2 exact-equality rule).

## Construction

1. **UserContentAttestationPayload signature preimage** (ADR 0010 §"Wire shape"):
   `dCBOR([attestation_id, attested_event_hash, attested_event_position,
   attestor, identity_attestation_ref, signing_intent, attested_at])`. See
   `input-uca-signature-preimage.cbor`.

2. **UserContentAttestationPayload.signature.** Sign the SHA-256 of the
   preimage under domain tag `trellis-user-content-attestation-v1` (Core §9.8)
   using `_keys/issuer-001.cose_key`. Detached Ed25519, 64 bytes. See
   `input-uca-signature.bin`. First 16 bytes: `69e2a1b8b009adcd6115bc2b94368746`.

3. **UserContentAttestationPayload** (Core §28 / ADR 0010 §"Wire shape"):
   the 11-field map carrying all signed fields plus `signing_kid` (issuer-001's
   16-byte derived kid, the `signing` key class). See `input-uca-payload.cbor`.

4. **EventPayload.extensions** carries the user-content-attestation payload
   under key `trellis.user-content-attestation.v1` (Core §6.7 registration row).

5. **Envelope.** Genesis sequence = 0, `prev_hash = null`, `ledger_scope =
   b'trellis-uca:test:037-multi'`. Standard Trellis Core §6 envelope; signed under
   `_keys/issuer-001.cose_key` (Ed25519, suite-id 1).

6. **Hashes.** Author/canonical hashes follow Core §9.5 / §9.1 framing.
   - `author_event_hash` = `1b5a74afc7a4d87dd5c2f062f8d62a3ca42e2d884ed3f28305c45f079125ae06`
   - `canonical_event_hash` = `d8f2f9ef4df5b2fedf30e8a1f3814bbc039a384a2336af06d8cea6768edfdeb3`

## Phase-1 verifier posture

Per `decode_user_content_attestation_payload` in
`integrity-verify::trellis`: this vector exercises step 1 (CDDL decode)
and step 2 partial (`attested_at == authored_at`; `signing_intent` RFC 3986
well-formedness) at the per-event path. Cross-event steps 3 / 4 / 5 / 6 / 7 / 8
require multi-event chain context and exercise via `tamper/028..034`.

Generator: `fixtures/vectors/_generator/gen_append_036_to_039.py`.
