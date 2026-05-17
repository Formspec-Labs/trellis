# Derivation — `append/028-certificate-of-completion-minimal-pdf`

ADR 0007 §"Wire shape" positive vector for `trellis.certificate-of-completion.v1`.

## Inputs

- Issuer key: `_keys/issuer-001.cose_key` (Ed25519 / suite-id 1).
- Presentation artifact: `presentation-artifact.bin` (64 deterministic bytes).
- Reference SignatureAffirmation: `append/019-wos-signature-affirmation`'s
  canonical event hash is the value of every `signing_events[i]` digest.

## Construction

1. **Presentation artifact content_hash.** Apply Core §9.1 domain-separated
   SHA-256 with tag `trellis-presentation-artifact-v1` over the artifact
   bytes. Result: `e218ce041e31c27636294ef0be46f05fa9ef5e396c18453b6dc57ea2e36a7775`.

2. **CertificateOfCompletionPayload.** Build per ADR 0007 §"Wire shape".
   Field choices:
   - `certificate_id` = `urn:trellis:certificate:test:028`
   - `case_ref` = `None`
   - `completed_at` = `[1776899500, 0]`
   - `presentation_artifact.media_type` = `'application/pdf'`
   - `presentation_artifact.template_id` = `None`
   - `presentation_artifact.template_hash` = `null`
   - `chain_summary.signer_count` = `1`
   - `chain_summary.workflow_status` = `'completed'`
   - `chain_summary.impact_level` = `None`
   - `signing_events` = [`<append/019 canonical_event_hash>` × 1]
   - `attestations` = 1 × `Attestation` row
     (Companion §A.5 shape; signed under `trellis-transition-attestation-v1`).

3. **EventPayload.extensions** carries the certificate payload under key
   `trellis.certificate-of-completion.v1` (Core §6.7 registration row).

4. **Envelope.** Genesis sequence = 0, `prev_hash = null`, `ledger_scope =
   b'trellis-cert:test:028-minimal'`. Standard Trellis Core §6 envelope; signed under
   `_keys/issuer-001.cose_key` (Ed25519, suite-id 1).

5. **Hashes.** Author/canonical hashes follow Core §9.5 / §9.1 framing.
   Final `canonical_event_hash` = `b2a7ffb1eeb030de1f05e062ee6a20f45b4cb8c704d61abd03aed749d0ca6bde`.

## Phase-1 verifier posture

Per `finalize_certificates_of_completion` in `integrity-verify::trellis`:
genesis-append context skips step 5 / 6 / 7 cross-event resolution because
the in-scope `events` slice does not carry the referenced
SignatureAffirmation. Step 4 (attachment lineage + content-hash recompute)
is wholly deferred to the export-bundle path — see
`export/010-certificate-of-completion-inline` for the resolvable lineage.

This vector therefore exercises:
- CDDL decode (step 1)
- Per-event chain-summary invariants (step 2 first clause):
  `signer_count == len(signing_events) == len(signer_display)`.
- Phase-1 structural attestation contract (step 3): each attestation row is
  64 bytes signed over the A.5 preimage.
- HTML→template_hash non-null rule (ADR 0007 §"Wire shape") iff
  `media_type = text/html` (vector 030).

Generator: `fixtures/vectors/_generator/gen_append_028_to_030.py`.
