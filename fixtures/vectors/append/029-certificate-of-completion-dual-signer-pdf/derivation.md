# Derivation — `append/029-certificate-of-completion-dual-signer-pdf`

ADR 0007 §"Wire shape" positive vector for `trellis.certificate-of-completion.v1`.

## Inputs

- Issuer key: `_keys/issuer-001.cose_key` (Ed25519 / suite-id 1).
- Presentation artifact: `presentation-artifact.bin` (64 deterministic bytes).
- Reference SignatureAffirmation: `append/019-wos-signature-affirmation`'s
  canonical event hash is the value of every `signing_events[i]` digest.

## Construction

1. **Presentation artifact content_hash.** Apply Core §9.1 domain-separated
   SHA-256 with tag `trellis-presentation-artifact-v1` over the artifact
   bytes. Result: `67f7668632296e0e03036c8fde8e4d75d971e54aaa060bf8cad1c79e6b1ad50e`.

2. **CertificateOfCompletionPayload.** Build per ADR 0007 §"Wire shape".
   Field choices:
   - `certificate_id` = `urn:trellis:certificate:test:029`
   - `case_ref` = `'urn:trellis:case:test-cert-029'`
   - `completed_at` = `[1776899500, 0]`
   - `presentation_artifact.media_type` = `'application/pdf'`
   - `presentation_artifact.template_id` = `'trellis.reference.certificate-of-completion.v1'`
   - `presentation_artifact.template_hash` = `non-null (32 bytes)`
   - `chain_summary.signer_count` = `2`
   - `chain_summary.workflow_status` = `'countersigned'`
   - `chain_summary.impact_level` = `'moderate'`
   - `signing_events` = [`<append/019 canonical_event_hash>` × 2]
   - `attestations` = 2 × `Attestation` row
     (Companion §A.5 shape; signed under `trellis-transition-attestation-v1`).

3. **EventPayload.extensions** carries the certificate payload under key
   `trellis.certificate-of-completion.v1` (Core §6.7 registration row).

4. **Envelope.** Genesis sequence = 0, `prev_hash = null`, `ledger_scope =
   b'trellis-cert:test:029-dual'`. Standard Trellis Core §6 envelope; signed under
   `_keys/issuer-001.cose_key` (Ed25519, suite-id 1).

5. **Hashes.** Author/canonical hashes follow Core §9.5 / §9.1 framing.
   Final `canonical_event_hash` = `949161c572b9fa471447d49bb0829295328a210bb7b35f7fbaa324f701af0c13`.

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
