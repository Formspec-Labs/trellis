# Derivation — `verify/014-export-006-signature-row-mismatch`

This fixture starts from `export/006-signature-affirmations-inline`, mutates the
`signing_act_id` in `062-signature-affirmations.cbor`, recomputes the catalog
digest, and re-signs `000-manifest.cbor`. The ZIP remains structurally valid
and all manifest digests match the archive contents, but the signature catalog
no longer matches the chain-authored WOS `SignatureAffirmation` payload.
