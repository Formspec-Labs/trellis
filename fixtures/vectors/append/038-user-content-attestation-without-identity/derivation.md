# Derivation — `append/038-user-content-attestation-without-identity`

ADR 0010 §"Wire shape" positive vector for `trellis.user-content-attestation.v1`.

## Inputs

- Issuer key: `_keys/issuer-001.cose_key` (Ed25519 / suite-id 1).
- `attestation_id` = `urn:trellis:user-content-attestation:test:038`
- `attested_event_hash` = `763194822ad4797482ea2ec982adbe7216e17cc82df59462e60dae29c27f6e1c` (deterministic
  fixture marker: `SHA-256("trellis-fixture-host-event:038")`).
- `attested_event_position` = `0`
- `attestor` = `urn:trellis:principal:applicant-038`
- `identity_attestation_ref` = `null` (Posture Declaration MUST admit unverified attestors)
- `signing_intent` = `urn:wos:signature-intent:public-comment` (RFC 3986 syntactically valid;
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
   `input-uca-signature.bin`. First 16 bytes: `de902ad69f98600ff611bd4d49cc5796`.

3. **UserContentAttestationPayload** (Core §28 / ADR 0010 §"Wire shape"):
   the 11-field map carrying all signed fields plus `signing_kid` (issuer-001's
   16-byte derived kid, the `signing` key class). See `input-uca-payload.cbor`.

4. **EventPayload.extensions** carries the user-content-attestation payload
   under key `trellis.user-content-attestation.v1` (Core §6.7 registration row).

5. **Envelope.** Genesis sequence = 0, `prev_hash = null`, `ledger_scope =
   b'trellis-uca:test:038-noident'`. Standard Trellis Core §6 envelope; signed under
   `_keys/issuer-001.cose_key` (Ed25519, suite-id 1).

6. **Hashes.** Author/canonical hashes follow Core §9.5 / §9.1 framing.
   - `author_event_hash` = `0c5f9589d97c45f1b2e4c79a75f3a1270b8bb3868a9f4ec20f935a0c4994ba86`
   - `canonical_event_hash` = `4dac71b9a0ff48c3e02441a323cd0804cad8c6cb95c799fbd913612e11afd6e7`

## Phase-1 verifier posture

Per `decode_user_content_attestation_payload` in
`integrity-verify::trellis`: this vector exercises step 1 (CDDL decode)
and step 2 partial (`attested_at == authored_at`; `signing_intent` RFC 3986
well-formedness) at the per-event path. Cross-event steps 3 / 4 / 5 / 6 / 7 / 8
require multi-event chain context and exercise via `tamper/028..034`.

Generator: `fixtures/vectors/_generator/gen_append_036_to_039.py`.
