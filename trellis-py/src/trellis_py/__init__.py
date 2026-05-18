"""Trellis Phase-1 Python implementation (append, verify, export) for vector conformance."""

from trellis_py._cbor_canonical import (
    CanonicalCborError,
    domain_separated_sha256,
    encode_canonical_cbor_value,
    encode_canonical_map_pairs,
)
from trellis_py._cbor_strict import (
    CborStrictError,
    reject_duplicate_canonical_map_keys,
)
from trellis_py.append import AppendArtifacts, append_event
from trellis_py.export_zip import ExportEntry, export_to_zip_bytes
from trellis_py.verify import VerificationReport, verify_export_zip, verify_tampered_ledger
from trellis_py.verify_wos import (
    derive_signed_acts_manifest_v1,
    encode_signed_acts_manifest_v1,
)

__all__ = [
    "AppendArtifacts",
    "append_event",
    "ExportEntry",
    "export_to_zip_bytes",
    "VerificationReport",
    "verify_export_zip",
    "verify_tampered_ledger",
    # Canonical CBOR §4.2.2 emission + parse-side dup-key walker (Task A2 / A2b).
    "CanonicalCborError",
    "CborStrictError",
    "domain_separated_sha256",
    "encode_canonical_cbor_value",
    "encode_canonical_map_pairs",
    "reject_duplicate_canonical_map_keys",
    # Signed-acts manifest derivation + canonical encoding (Task A5).
    "derive_signed_acts_manifest_v1",
    "encode_signed_acts_manifest_v1",
]
