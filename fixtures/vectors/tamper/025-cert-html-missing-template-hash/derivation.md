# Derivation — `tamper/025-cert-html-missing-template-hash`

Starts from `append/030-certificate-of-completion-html-template`. Sets
`presentation_artifact.template_hash = null` while leaving
`presentation_artifact.media_type = "text/html"`.

Per ADR 0007 §"Wire shape" `PresentationArtifact.template_hash`:

> When media_type = "text/html", MUST be non-null even if template_id is
> null (HTML binding requires a template pin)

`decode_certificate_payload` enforces this at decode time, returning
`Err(VerifyError::with_kind(..., "malformed_cose"))`. The §19.1 enum has
no dedicated tamper_kind for this case; the generic structure-failure
kind is correct for a CDDL-shape rejection at decode.

TR-OP-131 covers the operator-side discipline: HTML presentations MUST
ship with template_hash. This vector is the verifier-side gate.

Failing canonical_event_hash: `c4efa8720859bd6ae8a845cceafbd23c30bdb4f804c095bf9907d3470a6f0a4c`.

Generator: `_generator/gen_tamper_021_023_025_026.py`.
