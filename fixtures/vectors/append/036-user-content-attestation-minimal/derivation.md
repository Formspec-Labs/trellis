# Derivation — `append/036-user-content-attestation-minimal`

ADR 0010 §"Wire shape" positive vector for `trellis.user-content-attestation.v1`.

## Inputs

- Issuer key: `_keys/issuer-001.cose_key` (Ed25519 / suite-id 1).
- `attestation_id` = `urn:trellis:user-content-attestation:test:036`
- `attested_event_hash` = `5c58e79908420a4aca9acd898f7c9d2d9aef1d0e9f93de3ed462438a2df49bcd` (deterministic
  fixture marker: `SHA-256("trellis-fixture-host-event:036")`).
- `attested_event_position` = `0`
- `attestor` = `urn:trellis:principal:applicant-036`
- `identity_attestation_ref` = `c8ea3e8d0d8eadef08cc58f89b214eaea4e6a49704b85e4052d3ead5fbb07eb6` (32 bytes)
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
   `input-uca-signature.bin`. First 16 bytes: `6e1cdf8e8145f9f47c6369ca0b03998a`.

3. **UserContentAttestationPayload** (Core §28 / ADR 0010 §"Wire shape"):
   the 11-field map carrying all signed fields plus `signing_kid` (issuer-001's
   16-byte derived kid, the `signing` key class). See `input-uca-payload.cbor`.

4. **EventPayload.extensions** carries the user-content-attestation payload
   under key `trellis.user-content-attestation.v1` (Core §6.7 registration row).

5. **Envelope.** Genesis sequence = 0, `prev_hash = null`, `ledger_scope =
   b'trellis-uca:test:036-minimal'`. Standard Trellis Core §6 envelope; signed under
   `_keys/issuer-001.cose_key` (Ed25519, suite-id 1).

6. **Hashes.** Author/canonical hashes follow Core §9.5 / §9.1 framing.
   - `author_event_hash` = `3062aba6cf3f6a0109e58eb051378234209cf102a5c248afd299feb33a94665d`
   - `canonical_event_hash` = `f8e970ebf536e6411616a18fd0191503e83b23df2b21c7f2f7b25e7c99445cc6`

## Phase-1 verifier posture

Per `decode_user_content_attestation_payload` in
`integrity-verify::trellis`: this vector exercises step 1 (CDDL decode)
and step 2 partial (`attested_at == authored_at`; `signing_intent` RFC 3986
well-formedness) at the per-event path. Cross-event steps 3 / 4 / 5 / 6 / 7 / 8
require multi-event chain context and exercise via `tamper/028..034`.

Generator: `fixtures/vectors/_generator/gen_append_036_to_039.py`.
