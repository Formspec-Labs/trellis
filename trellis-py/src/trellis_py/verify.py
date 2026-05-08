"""Offline export ZIP and tamper-ledger verification (Core §19)."""

from __future__ import annotations

import io
import json
import zipfile
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Callable, NamedTuple, Optional, Protocol

import cbor2
from cbor2 import CBORDecodeError, CBORTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from trellis_py.codec import (
    domain_separated_sha256,
    encode_bstr,
    encode_tstr,
    encode_uint,
    sig_structure_bytes,
)
from trellis_py.constants import (
    ALG_EDDSA,
    AUTHOR_EVENT_DOMAIN,
    CHECKPOINT_DOMAIN,
    CONTENT_DOMAIN,
    COSE_LABEL_ALG,
    COSE_LABEL_KID,
    COSE_LABEL_SUITE_ID,
    EVENT_DOMAIN,
    MERKLE_INTERIOR_DOMAIN,
    MERKLE_LEAF_DOMAIN,
    POSTURE_DECLARATION_DOMAIN,
    SUITE_ID_PHASE_1,
)


class TrellisTimestamp:
    """Protobuf-pattern timestamp: [seconds, nanos] per ADR 0069 D-2.1."""
    __slots__ = ('seconds', 'nanos')

    def __init__(self, seconds: int, nanos: int = 0):
        assert isinstance(seconds, int) and seconds >= 0
        assert isinstance(nanos, int) and 0 <= nanos <= 999_999_999
        self.seconds = seconds
        self.nanos = nanos

    def __eq__(self, other):
        if not isinstance(other, TrellisTimestamp):
            return NotImplemented
        return self.seconds == other.seconds and self.nanos == other.nanos

    def __lt__(self, other):
        if not isinstance(other, TrellisTimestamp):
            return NotImplemented
        if self.seconds != other.seconds:
            return self.seconds < other.seconds
        return self.nanos < other.nanos

    def __le__(self, other):
        return self == other or self < other

    def __gt__(self, other):
        if not isinstance(other, TrellisTimestamp):
            return NotImplemented
        return other < self

    def __ge__(self, other):
        return self == other or self > other

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return f"TrellisTimestamp(seconds={self.seconds}, nanos={self.nanos})"

    def __hash__(self):
        return hash((self.seconds, self.nanos))

ATTACHMENT_EXPORT_EXTENSION = "trellis.export.attachments.v1"
ATTACHMENT_EVENT_EXTENSION = "trellis.evidence-attachment-binding.v1"
ERASURE_EVIDENCE_EVENT_EXTENSION = "trellis.erasure-evidence.v1"
ERASURE_EVIDENCE_EXPORT_EXTENSION = "trellis.export.erasure-evidence.v1"
ERASURE_EVIDENCE_CATALOG_MEMBER = "064-erasure-evidence.cbor"
# ADR 0007 §6.7 registration — `EventPayload.extensions` slot for
# certificate-of-completion records. Per-certificate inline shape per
# `CertificateOfCompletionPayload` in ADR 0007 §"Wire shape".
CERTIFICATE_EVENT_EXTENSION = "trellis.certificate-of-completion.v1"
# ADR 0007 §"Export manifest catalog" — optional manifest extension
# binding `065-certificates-of-completion.cbor`.
CERTIFICATE_EXPORT_EXTENSION = "trellis.export.certificates-of-completion.v1"
# ADR 0007 §9.8 / Core §9 — domain-separation tag for the SHA-256
# preimage covering rendered presentation-artifact bytes (PDF / HTML).
PRESENTATION_ARTIFACT_DOMAIN = "trellis-presentation-artifact-v1"
# ADR 0010 §6.7 registration — `EventPayload.extensions` slot for
# user-content-attestation records.
USER_CONTENT_ATTESTATION_EVENT_EXTENSION = "trellis.user-content-attestation.v1"
# ADR 0010 §9.8 — domain-separation tag for the dCBOR signature preimage.
USER_CONTENT_ATTESTATION_DOMAIN = "trellis-user-content-attestation-v1"
SUPERSEDES_CHAIN_ID_EVENT_EXTENSION = "trellis.supersedes-chain-id.v1"
SUPERSESSION_GRAPH_EXPORT_EXTENSION = "trellis.export.supersession-graph.v1"
SUPERSESSION_GRAPH_MEMBER = "064-supersession-graph.json"
SUPERSESSION_PREDECESSOR_PREFIX = "070-predecessors/"
OPEN_CLOCKS_EXPORT_EXTENSION = "trellis.export.open-clocks.v1"
OPEN_CLOCKS_MEMBER = "open-clocks.json"
# Phase-1 identity-attestation event type for fixtures. Core §6.7 + §10.6
# reserve `x-trellis-test/*` for fixture authoring. Consumer-owned identity
# taxonomies are admitted through composed verifier hooks.
PHASE_1_TEST_IDENTITY_EVENT_TYPE = "x-trellis-test/identity-attestation/v1"
# Companion §6.4 operator-URI prefix conventions (Phase-1 baseline). Step 8
# of ADR 0010 verifier obligations rejects user-content-attestation events
# whose `attestor` matches either prefix. Mirror Rust constants.
OPERATOR_URI_PREFIX_TRELLIS = "urn:trellis:operator:"
OPERATOR_URI_PREFIX_WOS = "urn:wos:operator:"


@dataclass
class VerificationFailure:
    kind: str
    location: str


@dataclass
class PostureTransitionOutcome:
    transition_id: str
    kind: str
    event_index: int
    from_state: str
    to_state: str
    continuity_verified: bool
    declaration_resolved: bool
    attestations_verified: bool
    failures: list[str] = field(default_factory=list)


@dataclass
class ErasureEvidenceOutcome:
    """Outcome for one cryptographic-erasure-evidence verification (ADR 0005
    step 10 / Core §19 step 6b). One entry per `trellis.erasure-evidence.v1`
    payload in the chain, in chain order. Mirrors Rust
    `trellis_verify::ErasureEvidenceOutcome` byte-for-byte.

    `signature_verified` is the Phase-1 structural check (every attestation
    row carries a 64-byte signature + recognized `authority_class`).
    Crypto-verification of the Ed25519 signatures themselves rides Phase-2+
    alongside the posture-transition flow.
    """

    evidence_id: str
    kid_destroyed: bytes
    destroyed_at: TrellisTimestamp
    cascade_scopes: list[str]
    completion_mode: str
    event_index: int
    signature_verified: bool
    post_erasure_uses: int = 0
    post_erasure_wraps: int = 0
    cascade_violations: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)


@dataclass
class CertificateOfCompletionOutcome:
    """Outcome for one ADR 0007 certificate-of-completion verification
    (Core §19 step 6c). One entry per `trellis.certificate-of-completion.v1`
    payload in scope, in chain order. Mirrors Rust
    `trellis_verify::CertificateOfCompletionOutcome` byte-for-byte.

    `attachment_resolved` / `all_signing_events_resolved` /
    `chain_summary_consistent` are the three booleans that participate in
    the §19 step-9 integrity fold; `failures` localizes the concrete
    tamper kinds (e.g. `signing_event_unresolved`,
    `presentation_artifact_content_mismatch`)."""

    certificate_id: str
    event_index: int
    completed_at: TrellisTimestamp
    signer_count: int
    attachment_resolved: bool = True
    all_signing_events_resolved: bool = True
    chain_summary_consistent: bool = True
    failures: list[str] = field(default_factory=list)


@dataclass
class UserContentAttestationOutcome:
    """Outcome for one ADR 0010 user-content-attestation verification
    (Core §19 step 6d). One entry per `trellis.user-content-attestation.v1`
    payload in scope, in chain order. Mirrors Rust
    `trellis_verify::UserContentAttestationOutcome`.

    `chain_position_resolved` / `identity_resolved` / `signature_verified`
    / `key_active` participate in the §19 step-9 integrity fold; `failures`
    localizes the concrete tamper kinds (e.g.
    `user_content_attestation_chain_position_mismatch`,
    `user_content_attestation_intent_malformed`)."""

    attestation_id: str
    attested_event_hash: bytes
    attestor: str
    signing_intent: str
    event_index: int
    chain_position_resolved: bool = True
    identity_resolved: bool = True
    signature_verified: bool = True
    key_active: bool = True
    failures: list[str] = field(default_factory=list)


@dataclass
class InteropSidecarVerificationEntry:
    """ADR 0008 §"Phase-1 verifier obligation" per-entry interop-sidecar
    outcome. One entry per `manifest.interop_sidecars[i]` walked under
    Wave 25 dispatch (today: `c2pa-manifest@v1`). Mirrors Rust
    `trellis_verify::InteropSidecarVerificationEntry` and Core §28
    CDDL byte-for-byte.

    Path-(b) discipline: digest-binds only — does NOT resolve `source_ref`
    or decode the C2PA manifest bytes (Core §16 ISC-05 — Python G-5
    oracle stays free of `c2pa` ecosystem deps).
    """

    kind: str
    path: str
    derivation_version: int
    content_digest_ok: bool = True
    kind_registered: bool = True
    phase_1_locked: bool = False
    failures: list[str] = field(default_factory=list)


@dataclass
class VerificationReport:
    structure_verified: bool = False
    integrity_verified: bool = False
    readability_verified: bool = False
    event_failures: list[VerificationFailure] = field(default_factory=list)
    checkpoint_failures: list[VerificationFailure] = field(default_factory=list)
    proof_failures: list[VerificationFailure] = field(default_factory=list)
    posture_transitions: list[PostureTransitionOutcome] = field(default_factory=list)
    erasure_evidence: list[ErasureEvidenceOutcome] = field(default_factory=list)
    certificates_of_completion: list[CertificateOfCompletionOutcome] = field(
        default_factory=list
    )
    user_content_attestations: list[UserContentAttestationOutcome] = field(
        default_factory=list
    )
    interop_sidecars: list[InteropSidecarVerificationEntry] = field(
        default_factory=list
    )
    warnings: list[str] = field(default_factory=list)

    @staticmethod
    def fatal(kind: str, warning: str) -> VerificationReport:
        return VerificationReport(
            structure_verified=False,
            integrity_verified=False,
            readability_verified=False,
            event_failures=[VerificationFailure(kind, "structure")],
            warnings=[warning],
        )


class VerifyError(Exception):
    """Exception raised when verifier inputs cannot be decoded.

    The optional ``kind`` attribute tags the structural-failure code (e.g.
    ``"key_entry_attributes_shape_mismatch"`` for ADR 0006 §8.7.1
    violations) so call sites such as ``verify_tampered_ledger`` and
    ``verify_export_zip`` can map the exception to a
    :class:`VerificationReport` with the matching ``tamper_kind``
    instead of bubbling the generic ``signing_key_registry_invalid``.
    """

    def __init__(self, message: str, kind: Optional[str] = None) -> None:
        super().__init__(message)
        self.kind: Optional[str] = kind


class CertificateResponseProof(NamedTuple):
    """Neutral certificate response-proof shape consumed by the core
    verifier. Mirror of Rust ``trellis_verify::certificate_proof::CertificateResponseProof``.

    Trellis Core MUST NOT inspect WOS, Formspec, or any other consumer-domain
    field names. It calls ``ResponseProofResolver.resolve`` against opaque
    payload bytes and either receives a ``CertificateResponseProof`` (the
    consumer-domain resolver knew how to read this payload), ``None`` (this
    payload is not a signing-event the resolver can interpret), or raises
    ``MalformedResponseDigestError`` (the payload claimed to carry a response
    proof but the proof is malformed — fail closed at the caller).
    """

    response_hash: bytes  # 32 bytes


class ResolverError(Exception):
    """Base class for resolver-side errors surfaced to Trellis Core."""


class MalformedResponseDigestError(ResolverError):
    """The payload claimed to carry a response proof but the proof is
    malformed. Phase M defines the surface; Phase N flips the
    ``WosFormspecResolver`` malformed-digest path from silent-skip to
    raising this error."""


class ResponseProofResolver(Protocol):
    """Consumer-domain resolver that reads opaque signing-event payload
    bytes and returns a ``CertificateResponseProof`` when the resolver
    recognizes the payload as a signing event with an embedded response
    proof. Mirror of Rust ``trellis_verify::certificate_proof::ResponseProofResolver``.

    Returns a ``CertificateResponseProof`` if this resolver can interpret
    the payload, ``None`` if not. Raises ``MalformedResponseDigestError``
    if the payload claimed to carry a proof but the proof is malformed —
    callers fail closed.
    """

    def resolve(self, payload_bytes: bytes) -> Optional[CertificateResponseProof]: ...

    def resolve_principal_ref(self, payload_bytes: bytes) -> Optional[str]: ...


class _NoopResponseProofResolver:
    """No-op resolver used by Trellis Core's default verification paths.
    Always returns ``None`` — every payload is treated as
    "not-recognizable", which preserves the prior ``continue`` behavior
    on Core-only verification paths (no consumer-domain field reading).
    """

    def resolve(self, payload_bytes: bytes) -> Optional[CertificateResponseProof]:
        return None

    def resolve_principal_ref(self, payload_bytes: bytes) -> Optional[str]:
        return None


@dataclass
class ParsedSign1:
    protected_bytes: bytes
    kid: bytes
    alg: int
    suite_id: int
    payload: Optional[bytes]
    signature: bytes


@dataclass
class SigningKeyEntry:
    public_key: bytes
    status: int
    valid_to: Optional[TrellisTimestamp]


@dataclass
class NonSigningKeyEntry:
    """A reserved non-signing `KeyEntry` (Core §8.7 / ADR 0006).

    Phase-1 verifiers track these so a signature attempt under a kid registered
    as `tenant-root`, `scope`, `subject`, or `recovery` can be flagged with
    `key_class_mismatch` (Core §8.7.3 step 4) rather than the generic
    `unresolvable_manifest_kid` failure.

    ``subject_valid_to`` is captured for ``subject``-class entries so a future
    Phase-1 ``KeyBagEntry``-mediated ``subject_wrap_after_valid_to`` enforcement
    can run without re-decoding the registry. Phase-1 ``KeyBagEntry.recipient``
    is opaque bytes (Core §9.4); ADR 0006 *Phase-1 runtime discipline* defers
    recipient-to-``subject`` kid binding to Phase-2+. The field is therefore
    captured-but-unused at runtime today; see ``tamper/025`` for the wire shape.
    """

    class_: str  # `class` is a Python keyword; trailing underscore by convention.
    subject_valid_to: Optional[TrellisTimestamp] = None


# Reserved non-signing class literals (Core §8.7).
_RESERVED_NON_SIGNING_KIND = frozenset({"tenant-root", "scope", "subject", "recovery"})

# ADR 0008 closed kind registry. Mirrors Rust
# `trellis_verify::INTEROP_SIDECAR_KIND_*` constants.
_INTEROP_SIDECAR_REGISTERED_KINDS = frozenset({
    "c2pa-manifest",
    "did-key-view",
    "scitt-receipt",
    "vc-jose-cose-event",
})

# Wave 25: c2pa-manifest@v1 is the only dispatched kind/version. The
# three other kinds in the registry are still locked-off; bumping the
# supported version set is wire-breaking per ISC-06.
_INTEROP_SIDECAR_C2PA_MANIFEST_SUPPORTED_VERSIONS = frozenset({1})

# ADR 0008 §"Export bundle layout" — sidecar files live under a single
# `interop-sidecars/` tree at the export root. Mirrors Rust
# `trellis_verify::INTEROP_SIDECARS_PATH_PREFIX`.
_INTEROP_SIDECARS_PATH_PREFIX = "interop-sidecars/"


def _is_interop_sidecar_path_valid(path: str) -> bool:
    """TR-CORE-167 — byte-prefix check. Mirrors Rust
    `trellis_verify::is_interop_sidecar_path_valid`. No normalization,
    no Unicode folding, case-sensitive."""
    return path.startswith(_INTEROP_SIDECARS_PATH_PREFIX)


@dataclass
class RegistryBindingInfo:
    digest_hex: str
    bound_at_sequence: int


@dataclass
class BoundRegistry:
    event_types: list[str]
    classifications: list[str]


@dataclass
class AttachmentBindingDetails:
    attachment_id: str
    slot_path: str
    media_type: str
    byte_length: int
    attachment_sha256: bytes
    payload_content_hash: bytes
    filename: Optional[str]
    prior_binding_hash: Optional[bytes]


@dataclass(frozen=True)
class SupersedesChainIdDetails:
    chain_id: bytes
    checkpoint_hash: bytes


@dataclass
class EventDetails:
    scope: bytes
    sequence: int
    authored_at: TrellisTimestamp
    event_type: str
    classification: str
    prev_hash: Optional[bytes]
    author_event_hash: bytes
    content_hash: bytes
    canonical_event_hash: bytes
    # Core §6.1 / §17.2 wire-contract identity. Length is validated against
    # `bstr .size (1..64)` at parse time; out-of-bound length surfaces as a
    # typed VerifyError with kind "idempotency_key_length_invalid". Used by
    # the per-event-set loop to detect §17.3 duplicate (scope, key) identity
    # with divergent canonical material. TR-CORE-158, TR-CORE-160, TR-CORE-161.
    idempotency_key: bytes
    payload_ref_inline: Optional[bytes]
    payload_ref_external: bool
    transition: Optional["TransitionDetails"]
    attachment_binding: Optional[AttachmentBindingDetails] = None
    erasure: Optional["ErasureEvidenceDetails"] = None
    certificate: Optional["CertificateDetails"] = None
    user_content_attestation: Optional["UserContentAttestationDetails"] = None
    # ADR 0066 / Core §19 step 6e. Export-bundle verification cross-checks
    # this event-level linkage against `064-supersession-graph.json`.
    supersedes_chain: Optional[SupersedesChainIdDetails] = None
    # Identity-attestation subject for events whose `event_type` matches
    # `_is_identity_attestation_event_type`. Read from
    # `extensions[event_type]["subject"]`. ADR 0010 verifier obligations
    # step 4 (subject-equals-attestor) reads this.
    identity_attestation_subject: Optional[str] = None
    wrap_recipients: list[bytes] = field(default_factory=list)


@dataclass
class TransitionDetails:
    # "custody-model" or "disclosure-profile" — routes shadow-state lookup
    # and attestation rule per Companion Appendix A.5.3. Mirrors the Rust
    # TransitionKind enum in trellis-verify/src/lib.rs.
    kind: str
    transition_id: str
    from_state: str
    to_state: str
    declaration_digest: bytes
    attestation_classes: list[str]
    # Only populated for disclosure-profile transitions. Drives the
    # Narrowing / Widening / Orthogonal attestation rule (A.5.3 step 4).
    scope_change: Optional[str] = None



@dataclass
class ErasureEvidenceDetails:
    """Decoded `trellis.erasure-evidence.v1` payload (ADR 0005 §"Wire shape").

    Mirrors Rust `trellis_verify::ErasureEvidenceDetails`. `norm_key_class`
    holds the wire `key_class` AFTER `wrap` → `subject` normalization (Core
    §8.7.6 / ADR 0005 step 2) so cross-event step 5 / step 8 reasoning
    operates on the canonical taxonomy.
    """

    evidence_id: str
    kid_destroyed: bytes
    norm_key_class: str
    destroyed_at: TrellisTimestamp
    cascade_scopes: list[str]
    completion_mode: str
    attestation_signatures_well_formed: bool
    attestation_classes: list[str]
    subject_scope_kind: str


@dataclass
class SignerDisplayDetails:
    """Decoded `SignerDisplayEntry` (ADR 0007 §"Wire shape")."""

    principal_ref: str
    display_name: str
    display_role: Optional[str]
    signed_at: TrellisTimestamp


@dataclass
class PresentationArtifactDetails:
    """Decoded `PresentationArtifact` (ADR 0007 §"Wire shape")."""

    content_hash: bytes
    media_type: str
    byte_length: int
    attachment_id: str
    template_id: Optional[str]
    template_hash: Optional[bytes]


@dataclass
class ChainSummaryDetails:
    """Decoded `ChainSummary` (ADR 0007 §"Wire shape")."""

    signer_count: int
    signer_display: list[SignerDisplayDetails]
    response_ref: Optional[bytes]
    workflow_status: str
    impact_level: Optional[str]
    covered_claims: list[str]


@dataclass
class CertificateDetails:
    """Decoded `trellis.certificate-of-completion.v1` payload (ADR 0007
    §"Wire shape"). Mirrors Rust `trellis_verify::CertificateDetails`.

    `attestation_signatures_well_formed` is the Phase-1 structural check
    (every attestation row carries a 64-byte signature + recognized
    `authority_class`). Crypto-verification of the Ed25519 signature itself
    rides Phase-2+ alongside the posture-transition flow."""

    certificate_id: str
    case_ref: Optional[str]
    completed_at: TrellisTimestamp
    presentation_artifact: PresentationArtifactDetails
    chain_summary: ChainSummaryDetails
    signing_events: list[bytes]
    workflow_ref: Optional[str]
    attestation_signatures_well_formed: bool


@dataclass
class UserContentAttestationDetails:
    """Decoded `trellis.user-content-attestation.v1` payload (ADR 0010
    §"Wire shape" / Core §28 CDDL `UserContentAttestationPayload`). Mirrors
    Rust `trellis_verify::UserContentAttestationDetails`.

    `step_2_failure` is the deferred-failure marker per ADR 0010 §"Verifier
    obligations" step 2: intra-payload-invariant failures
    (`user_content_attestation_intent_malformed` /
    `user_content_attestation_timestamp_mismatch`) flip
    `integrity_verified = false` only — they are NOT structure failures
    and MUST NOT flip `readability_verified`. Decoder records the marker;
    `_finalize_user_content_attestations` raises it as an `event_failure`
    and skips remaining per-event checks for this attestation."""

    attestation_id: str
    attested_event_hash: bytes
    attested_event_position: int
    attestor: str
    identity_attestation_ref: Optional[bytes]
    signing_intent: str
    attested_at: TrellisTimestamp
    signature: bytes
    signing_kid: bytes
    canonical_preimage: bytes
    step_2_failure: Optional[str] = None


@dataclass
class _ChainEventSummary:
    """Per-event chain summary used by ADR 0005 step 8 cross-event walk."""

    event_index: int
    authored_at: TrellisTimestamp
    signing_kid: bytes
    wrap_recipients: list[bytes]
    canonical_event_hash: bytes


def _sha256(b: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(b).digest()


def _hex(b: bytes) -> str:
    return b.hex()


def _hex_decode(text: str) -> bytes:
    if len(text) % 2:
        raise VerifyError("hex string must have even length")
    out = bytearray()
    for i in range(0, len(text), 2):
        out.append(int(text[i : i + 2], 16))
    return bytes(out)


def _decode_value(data: bytes) -> Any:
    try:
        return cbor2.loads(data)
    except Exception as exc:  # noqa: BLE001
        raise VerifyError(f"failed to decode CBOR: {exc}") from exc


def _map_lookup_str(m: dict, key: str) -> Any:
    if key not in m:
        raise VerifyError(f"missing `{key}`")
    return m[key]


def _map_lookup_optional_str(m: dict, key: str) -> Any:
    return m.get(key)


def _map_lookup_bytes(m: dict, key: str) -> bytes:
    v = _map_lookup_str(m, key)
    if not isinstance(v, bytes):
        raise VerifyError(f"`{key}` is not bytes")
    return v


def _map_lookup_fixed_bytes(m: dict, key: str, n: int) -> bytes:
    b = _map_lookup_bytes(m, key)
    if len(b) != n:
        raise VerifyError(f"`{key}` must be {n} bytes")
    return b


def _map_lookup_u64(m: dict, key: str) -> int:
    v = _map_lookup_str(m, key)
    if not isinstance(v, int) or v < 0:
        raise VerifyError(f"`{key}` is not an unsigned integer")
    return v


def _map_lookup_timestamp(m: dict, key: str) -> TrellisTimestamp:
    v = m.get(key)
    if v is None:
        raise VerifyError(f"missing required field: {key}")
    if isinstance(v, list) and len(v) == 2:
        seconds = v[0]
        nanos = v[1]
        if not isinstance(seconds, int) or seconds < 0:
            raise VerifyError(f"{key} seconds must be non-negative uint, got {seconds!r}")
        if not isinstance(nanos, int) or nanos < 0 or nanos > 999_999_999:
            raise VerifyError(
                f"{key} nanos must be 0..999999999, got {nanos!r}",
                kind="timestamp_nanos_out_of_range",
            )
        return TrellisTimestamp(seconds, nanos)
    if isinstance(v, int):
        raise VerifyError(
            f"{key} is legacy uint format; expected [seconds, nanos] array per ADR 0069 D-2.1",
            kind="legacy_timestamp_format",
        )
    raise VerifyError(f"{key} must be [uint, uint] array, got {type(v).__name__}")


def _map_lookup_bool(m: dict, key: str) -> bool:
    v = _map_lookup_str(m, key)
    if not isinstance(v, bool):
        raise VerifyError(f"`{key}` is not a bool")
    return v


def _map_lookup_optional_fixed_bytes(m: dict, key: str, n: int) -> Optional[bytes]:
    v = m.get(key)
    if v is None:
        return None
    if not isinstance(v, bytes) or len(v) != n:
        raise VerifyError(f"`{key}` must be {n} bytes or absent")
    return v


def _parse_sha256_prefix_text(value: str) -> bytes:
    if not value.startswith("sha256:"):
        raise VerifyError("hash text must use sha256: prefix")
    hx = value[len("sha256:") :]
    return _parse_sha256_hex(hx)


def _parse_sha256_hex(value: str) -> bytes:
    raw = _hex_decode(value)
    if len(raw) != 32:
        raise VerifyError("sha256 hash text must be 32 bytes")
    return raw


def _map_lookup_optional_bytes(m: dict, key: str) -> Optional[bytes]:
    v = _map_lookup_optional_str(m, key)
    if v is None:
        return None
    if v is False:  # cbor2 undefined? unlikely
        pass
    if isinstance(v, bytes):
        return v
    if v is None or (isinstance(v, type(None))):  # noqa: E721
        return None
    raise VerifyError(f"`{key}` is neither bytes nor null")


def _map_lookup_int_label(m: dict, label: int) -> int:
    if label not in m:
        raise VerifyError(f"missing COSE label {label} integer")
    v = m[label]
    if not isinstance(v, int):
        raise VerifyError("not int")
    return v


def _map_lookup_int_label_bytes(m: dict, label: int) -> bytes:
    if label not in m:
        raise VerifyError(f"missing COSE label {label} bytes")
    v = m[label]
    if not isinstance(v, bytes):
        raise VerifyError("not bytes")
    return v


def _parse_sign1_value(value: Any) -> ParsedSign1:
    if not isinstance(value, CBORTag) or value.tag != 18:
        raise VerifyError("value is not a tag-18 COSE_Sign1 item")
    body = value.value
    if not isinstance(body, (list, tuple)) or len(body) != 4:
        raise VerifyError("COSE_Sign1 body does not contain four fields")
    protected_bytes = body[0]
    unprotected = body[1]
    payload_field = body[2]
    sig_field = body[3]
    if not isinstance(protected_bytes, bytes):
        raise VerifyError("protected header is not a byte string")
    if not isinstance(unprotected, Mapping) or len(unprotected) != 0:
        raise VerifyError("unprotected header map must be empty")
    if isinstance(payload_field, bytes):
        payload: Optional[bytes] = payload_field
    elif payload_field is None:
        payload = None
    else:
        raise VerifyError("payload is neither bytes nor null")
    if not isinstance(sig_field, bytes) or len(sig_field) != 64:
        raise VerifyError("signature is not 64 bytes")
    protected_value = _decode_value(protected_bytes)
    if not isinstance(protected_value, dict):
        raise VerifyError("protected header does not decode to a map")
    kid = _map_lookup_int_label_bytes(protected_value, COSE_LABEL_KID)
    alg = _map_lookup_int_label(protected_value, COSE_LABEL_ALG)
    suite_id = _map_lookup_int_label(protected_value, COSE_LABEL_SUITE_ID)
    return ParsedSign1(
        protected_bytes=protected_bytes,
        kid=kid,
        alg=alg,
        suite_id=suite_id,
        payload=payload,
        signature=sig_field,
    )


def _parse_sign1_bytes(data: bytes) -> ParsedSign1:
    return _parse_sign1_value(_decode_value(data))


def _parse_sign1_array(data: bytes) -> list[ParsedSign1]:
    v = _decode_value(data)
    if not isinstance(v, (list, tuple)):
        raise VerifyError("expected a dCBOR array")
    return [_parse_sign1_value(item) for item in v]


def _verify_signature(item: ParsedSign1, public_key_bytes: bytes) -> bool:
    if item.payload is None:
        return False
    try:
        vk = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except Exception:  # noqa: BLE001
        return False
    msg = sig_structure_bytes(item.protected_bytes, item.payload)
    try:
        vk.verify(item.signature, msg)
        return True
    except Exception:  # noqa: BLE001
        return False


def _encode_tstr_cbor(s: str) -> bytes:
    return encode_tstr(s)


def _authored_preimage_from_canonical(canonical_event_bytes: bytes) -> Optional[bytes]:
    key = _encode_tstr_cbor("author_event_hash")
    key_pos = canonical_event_bytes.rfind(key)
    if key_pos < 0:
        return None
    value_pos = key_pos + len(key)
    if len(canonical_event_bytes) != value_pos + 34:
        return None
    if canonical_event_bytes[value_pos] != 0x58 or canonical_event_bytes[value_pos + 1] != 0x20:
        return None
    new_prefix = canonical_event_bytes[0] - 1
    if new_prefix < 0:
        return None
    authored = bytearray()
    authored.append(new_prefix)
    authored.extend(canonical_event_bytes[1:key_pos])
    return bytes(authored)


def _recompute_author_event_hash(canonical_event_bytes: bytes) -> Optional[bytes]:
    authored = _authored_preimage_from_canonical(canonical_event_bytes)
    if authored is None:
        return None
    return domain_separated_sha256(AUTHOR_EVENT_DOMAIN, authored)


def _recompute_canonical_event_hash(scope: bytes, canonical_event_bytes: bytes) -> bytes:
    preimage = bytearray()
    preimage.append(0xA3)
    preimage.extend(encode_tstr("version"))
    preimage.extend(encode_uint(1))
    preimage.extend(encode_tstr("ledger_scope"))
    preimage.extend(encode_bstr(scope))
    preimage.extend(encode_tstr("event_payload"))
    preimage.extend(canonical_event_bytes)
    return domain_separated_sha256(EVENT_DOMAIN, bytes(preimage))


def _decode_transition_details(extensions: dict) -> Optional[TransitionDetails]:
    ext_custody = extensions.get("trellis.custody-model-transition.v1")
    ext_disclosure = extensions.get("trellis.disclosure-profile-transition.v1")
    if ext_custody is not None and ext_disclosure is not None:
        raise VerifyError(
            "extensions MUST NOT contain both trellis.custody-model-transition.v1 and "
            "trellis.disclosure-profile-transition.v1 on the same event"
        )
    if ext_custody is not None:
        return _decode_custody_model_transition(ext_custody)
    if ext_disclosure is not None:
        return _decode_disclosure_profile_transition(ext_disclosure)
    return None


def _decode_custody_model_transition(ext: object) -> TransitionDetails:
    if not isinstance(ext, dict):
        raise VerifyError("custody-model transition extension is not a map")
    tid = str(_map_lookup_str(ext, "transition_id"))
    fs = str(_map_lookup_str(ext, "from_custody_model"))
    ts = str(_map_lookup_str(ext, "to_custody_model"))
    _ = _map_lookup_timestamp(ext, "effective_at")
    dd = _map_lookup_fixed_bytes(ext, "declaration_doc_digest", 32)
    classes = _decode_attestation_classes(ext)
    return TransitionDetails(
        kind="custody-model",
        transition_id=tid,
        from_state=fs,
        to_state=ts,
        declaration_digest=dd,
        attestation_classes=classes,
        scope_change=None,
    )


def _decode_disclosure_profile_transition(ext: object) -> TransitionDetails:
    if not isinstance(ext, dict):
        raise VerifyError("disclosure-profile transition extension is not a map")
    tid = str(_map_lookup_str(ext, "transition_id"))
    fs = str(_map_lookup_str(ext, "from_disclosure_profile"))
    ts = str(_map_lookup_str(ext, "to_disclosure_profile"))
    _ = _map_lookup_timestamp(ext, "effective_at")
    dd = _map_lookup_fixed_bytes(ext, "declaration_doc_digest", 32)
    sc = str(_map_lookup_str(ext, "scope_change"))
    classes = _decode_attestation_classes(ext)
    return TransitionDetails(
        kind="disclosure-profile",
        transition_id=tid,
        from_state=fs,
        to_state=ts,
        declaration_digest=dd,
        attestation_classes=classes,
        scope_change=sc,
    )


def _decode_attestation_classes(ext: dict) -> list[str]:
    atts = _map_lookup_str(ext, "attestations")
    if not isinstance(atts, list):
        raise VerifyError("attestations not array")
    classes: list[str] = []
    for item in atts:
        if not isinstance(item, dict):
            continue
        ac = item.get("authority_class")
        if isinstance(ac, str):
            classes.append(ac)
    return classes


def _decode_attachment_binding_details(exts: dict) -> Optional[AttachmentBindingDetails]:
    ext = exts.get(ATTACHMENT_EVENT_EXTENSION)
    if ext is None:
        return None
    if not isinstance(ext, dict):
        raise VerifyError("attachment binding extension is not a map")
    attachment_id = str(_map_lookup_str(ext, "attachment_id"))
    slot_path = str(_map_lookup_str(ext, "slot_path"))
    media_type = str(_map_lookup_str(ext, "media_type"))
    byte_length = _map_lookup_u64(ext, "byte_length")
    att_txt = str(_map_lookup_str(ext, "attachment_sha256"))
    pay_txt = str(_map_lookup_str(ext, "payload_content_hash"))
    attachment_sha256 = _parse_sha256_prefix_text(att_txt)
    payload_content_hash = _parse_sha256_prefix_text(pay_txt)
    fn_raw = _map_lookup_optional_str(ext, "filename")
    filename: Optional[str]
    if fn_raw is None:
        filename = None
    elif isinstance(fn_raw, str):
        filename = fn_raw
    else:
        raise VerifyError("filename invalid")
    prior_binding_hash: Optional[bytes]
    pb = ext.get("prior_binding_hash")
    if pb is None:
        prior_binding_hash = None
    elif isinstance(pb, bytes) and len(pb) == 32:
        prior_binding_hash = pb
    else:
        raise VerifyError("prior_binding_hash is neither 32 bytes nor null")
    return AttachmentBindingDetails(
        attachment_id=attachment_id,
        slot_path=slot_path,
        media_type=media_type,
        byte_length=byte_length,
        attachment_sha256=attachment_sha256,
        payload_content_hash=payload_content_hash,
        filename=filename,
        prior_binding_hash=prior_binding_hash,
    )


def _decode_certificate_payload(exts: dict) -> Optional[CertificateDetails]:
    """Decodes the optional `trellis.certificate-of-completion.v1` extension
    payload and runs ADR 0007 §"Verifier obligations" step 1 (CDDL decode +
    per-event chain-summary invariants) inline. Mirrors Rust
    `decode_certificate_payload` byte-for-byte.

    Cross-event steps 2 (id collision), 4 (attachment lineage), 5 (signing-
    event resolution), 6 (timestamp equivalence), 7 (response_ref
    equivalence) run in `_finalize_certificates_of_completion` after every
    event has been decoded.

    Per-event invariants enforced here:
    * `signer_count == len(signing_events)` (ADR 0007 step 2 first clause;
      `certificate_chain_summary_mismatch`)
    * `len(signer_display) == len(signing_events)` (same step; same kind)
    * HTML media type carries non-null `template_hash` (ADR 0007 §"Wire
      shape" `PresentationArtifact.template_hash`; emitted as a structure
      failure via `malformed_cose` because §19.1 has no dedicated tamper_kind
      for this case)
    """
    ext = exts.get(CERTIFICATE_EVENT_EXTENSION)
    if ext is None:
        return None
    if not isinstance(ext, dict):
        raise VerifyError("certificate-of-completion extension is not a map")

    certificate_id = str(_map_lookup_str(ext, "certificate_id"))
    case_ref_raw = _map_lookup_optional_str(ext, "case_ref")
    case_ref = case_ref_raw if (case_ref_raw is None or isinstance(case_ref_raw, str)) else None
    if case_ref_raw is not None and not isinstance(case_ref_raw, str):
        raise VerifyError("certificate `case_ref` is neither text nor null")
    completed_at = _map_lookup_timestamp(ext, "completed_at")

    # PresentationArtifact decode.
    pa = ext.get("presentation_artifact")
    if pa is None:
        raise VerifyError("certificate `presentation_artifact` is missing")
    if not isinstance(pa, dict):
        raise VerifyError("certificate `presentation_artifact` is not a map")
    pa_content_hash = _map_lookup_fixed_bytes(pa, "content_hash", 32)
    pa_media_type = str(_map_lookup_str(pa, "media_type"))
    pa_byte_length = _map_lookup_u64(pa, "byte_length")
    pa_attachment_id = str(_map_lookup_str(pa, "attachment_id"))
    pa_template_id_raw = _map_lookup_optional_str(pa, "template_id")
    pa_template_id: Optional[str]
    if pa_template_id_raw is None:
        pa_template_id = None
    elif isinstance(pa_template_id_raw, str):
        pa_template_id = pa_template_id_raw
    else:
        raise VerifyError("certificate presentation_artifact.template_id is neither text nor null")
    pa_template_hash = _map_lookup_optional_fixed_bytes(pa, "template_hash", 32)
    # ADR 0007 §"Wire shape" PresentationArtifact.template_hash: when
    # media_type = "text/html", template_hash MUST be non-null even when
    # template_id is null. §19.1 has no dedicated tamper_kind; surface as
    # a generic structure failure via `malformed_cose`.
    if pa_media_type == "text/html" and pa_template_hash is None:
        raise VerifyError(
            'certificate presentation_artifact: media_type=text/html requires template_hash to be non-null (ADR 0007 §Wire shape)',
            kind="malformed_cose",
        )

    # ChainSummary decode + per-event invariants.
    cs = ext.get("chain_summary")
    if cs is None:
        raise VerifyError("certificate `chain_summary` is missing")
    if not isinstance(cs, dict):
        raise VerifyError("certificate `chain_summary` is not a map")
    signer_count = _map_lookup_u64(cs, "signer_count")
    signer_display_array = _map_lookup_array(cs, "signer_display")
    if not signer_display_array:
        raise VerifyError(
            'certificate `chain_summary.signer_display` MUST be non-empty (ADR 0007 §Wire shape)'
        )
    signer_display: list[SignerDisplayDetails] = []
    for entry in signer_display_array:
        if not isinstance(entry, dict):
            raise VerifyError("signer_display entry is not a map")
        principal_ref = str(_map_lookup_str(entry, "principal_ref"))
        display_name = str(_map_lookup_str(entry, "display_name"))
        display_role_raw = _map_lookup_optional_str(entry, "display_role")
        if display_role_raw is None:
            display_role = None
        elif isinstance(display_role_raw, str):
            display_role = display_role_raw
        else:
            raise VerifyError("signer_display entry display_role is neither text nor null")
        signed_at = _map_lookup_timestamp(entry, "signed_at")
        signer_display.append(
            SignerDisplayDetails(
                principal_ref=principal_ref,
                display_name=display_name,
                display_role=display_role,
                signed_at=signed_at,
            )
        )
    response_ref = _map_lookup_optional_fixed_bytes(cs, "response_ref", 32)
    workflow_status = str(_map_lookup_str(cs, "workflow_status"))
    impact_level_raw = _map_lookup_optional_str(cs, "impact_level")
    if impact_level_raw is None:
        impact_level: Optional[str] = None
    elif isinstance(impact_level_raw, str):
        impact_level = impact_level_raw
    else:
        raise VerifyError("certificate chain_summary.impact_level is neither text nor null")
    covered_claims_raw = cs.get("covered_claims")
    if covered_claims_raw is None:
        covered_claims: list[str] = []
    elif isinstance(covered_claims_raw, list):
        covered_claims = []
        for tag in covered_claims_raw:
            if not isinstance(tag, str):
                raise VerifyError("certificate covered_claims entry is not text")
            covered_claims.append(tag)
    else:
        raise VerifyError("certificate `chain_summary.covered_claims` is not an array")

    # signing_events decode.
    signing_events_array = _map_lookup_array(ext, "signing_events")
    if not signing_events_array:
        raise VerifyError(
            'certificate `signing_events` MUST be non-empty (ADR 0007 §Wire shape)'
        )
    signing_events: list[bytes] = []
    for digest in signing_events_array:
        if not isinstance(digest, bytes):
            raise VerifyError("signing_events entry is not a byte string")
        if len(digest) != 32:
            raise VerifyError("signing_events entry is not 32 bytes")
        signing_events.append(digest)

    # ADR 0007 §"Verifier obligations" step 2 first invariant: per-event
    # shape (signer_count == len(signing_events) AND len(signer_display) ==
    # len(signing_events)). Mismatch flips integrity via the
    # `certificate_chain_summary_mismatch` tamper_kind.
    if signer_count != len(signing_events) or len(signer_display) != len(signing_events):
        raise VerifyError(
            f"certificate chain_summary invariant violated: signer_count={signer_count}, "
            f"signing_events={len(signing_events)}, signer_display={len(signer_display)} "
            "(ADR 0007 §Verifier obligations step 2)",
            kind="certificate_chain_summary_mismatch",
        )

    workflow_ref_raw = _map_lookup_optional_str(ext, "workflow_ref")
    if workflow_ref_raw is None:
        workflow_ref: Optional[str] = None
    elif isinstance(workflow_ref_raw, str):
        workflow_ref = workflow_ref_raw
    else:
        raise VerifyError("certificate `workflow_ref` is neither text nor null")

    # Step 3 (Phase-1 structural): every attestation row carries a 64-byte
    # signature and a recognized `authority_class`. Crypto-verification of
    # the Ed25519 signature itself rides Phase-2+.
    attestations = _map_lookup_array(ext, "attestations")
    if not attestations:
        raise VerifyError(
            'certificate `attestations` MUST be non-empty (ADR 0007 §Wire shape)'
        )
    attestation_signatures_well_formed = True
    for entry in attestations:
        if not isinstance(entry, dict):
            raise VerifyError("attestation entry is not a map")
        _ = str(_map_lookup_str(entry, "authority_class"))
        sig = _map_lookup_bytes(entry, "signature")
        if len(sig) != 64:
            attestation_signatures_well_formed = False
        _ = str(_map_lookup_str(entry, "authority"))

    return CertificateDetails(
        certificate_id=certificate_id,
        case_ref=case_ref,
        completed_at=completed_at,
        presentation_artifact=PresentationArtifactDetails(
            content_hash=pa_content_hash,
            media_type=pa_media_type,
            byte_length=pa_byte_length,
            attachment_id=pa_attachment_id,
            template_id=pa_template_id,
            template_hash=pa_template_hash,
        ),
        chain_summary=ChainSummaryDetails(
            signer_count=signer_count,
            signer_display=signer_display,
            response_ref=response_ref,
            workflow_status=workflow_status,
            impact_level=impact_level,
            covered_claims=covered_claims,
        ),
        signing_events=signing_events,
        workflow_ref=workflow_ref,
        attestation_signatures_well_formed=attestation_signatures_well_formed,
    )


def _normalize_cbor_compare(obj: Any) -> Any:
    """RFC8949-style map key ordering for semantic nested-map equality."""
    if isinstance(obj, dict):
        parts: list[tuple[bytes, Any, Any]] = []
        for k, v in obj.items():
            nk = _normalize_cbor_compare(k)
            nv = _normalize_cbor_compare(v)
            kb = cbor2.dumps(nk, canonical=True)
            parts.append((kb, nk, nv))
        parts.sort(key=lambda x: x[0])
        return tuple((k, v) for _, k, v in parts)
    if isinstance(obj, list):
        return tuple(_normalize_cbor_compare(x) for x in obj)
    if isinstance(obj, CBORTag):
        return ("tag", obj.tag, _normalize_cbor_compare(obj.value))
    return obj


def _cbor_nested_semantic_eq(a: Any, b: Any) -> bool:
    return _normalize_cbor_compare(a) == _normalize_cbor_compare(b)


def _validate_subject_scope_shape(subject_scope: dict, kind: str) -> None:
    """ADR 0005 step 3 — validates the cross-field shape of `subject_scope`.

    Mirrors Rust `validate_subject_scope_shape`. Raises VerifyError on any
    structural violation.
    """

    subject_refs = subject_scope.get("subject_refs")
    ledger_scopes = subject_scope.get("ledger_scopes")
    tenant_refs = subject_scope.get("tenant_refs")

    def is_present(v: Any) -> bool:
        return isinstance(v, list) and len(v) > 0

    def is_null_or_absent(v: Any) -> bool:
        if v is None:
            return True
        if isinstance(v, list) and len(v) == 0:
            return True
        return False

    if kind == "per-subject":
        ok = is_present(subject_refs) and is_null_or_absent(ledger_scopes) and is_null_or_absent(tenant_refs)
    elif kind == "per-scope":
        ok = is_null_or_absent(subject_refs) and is_present(ledger_scopes) and is_null_or_absent(tenant_refs)
    elif kind == "per-tenant":
        ok = is_null_or_absent(subject_refs) and is_null_or_absent(ledger_scopes) and is_present(tenant_refs)
    elif kind == "deployment-wide":
        ok = is_null_or_absent(subject_refs) and is_null_or_absent(ledger_scopes) and is_null_or_absent(tenant_refs)
    else:
        raise VerifyError(
            f"erasure-evidence subject_scope.kind `{kind}` is not one of "
            "per-subject / per-scope / per-tenant / deployment-wide (ADR 0005 step 3)"
        )

    if not ok:
        raise VerifyError(
            f"erasure-evidence subject_scope cross-field shape violates ADR 0005 step 3 for kind `{kind}`"
        )


def _decode_erasure_evidence_details(
    extensions: dict, host_authored_at: TrellisTimestamp
) -> Optional[ErasureEvidenceDetails]:
    """Decodes the optional `trellis.erasure-evidence.v1` extension payload
    and runs ADR 0005 §"Verifier obligations" steps 1 (CDDL), 3 (subject_scope
    shape), 4 (`destroyed_at` ≤ host `authored_at`), and 6 (hsm_receipt
    null-consistency) inline. Steps 2 / 5 / 7 / 8 / 9 / 10 run in the
    cross-event finalization pass after every event has been decoded.

    Mirrors Rust `decode_erasure_evidence_details` byte-for-byte.
    """

    ext = extensions.get(ERASURE_EVIDENCE_EVENT_EXTENSION)
    if ext is None:
        return None
    if not isinstance(ext, dict):
        raise VerifyError("erasure-evidence extension is not a map")

    # Step 1: CDDL decode. Required fields per ADR 0005 §"Wire shape".
    evidence_id = str(_map_lookup_str(ext, "evidence_id"))
    kid_destroyed = _map_lookup_fixed_bytes(ext, "kid_destroyed", 16)

    # Step 2 prep: capture `key_class` and apply `wrap` → `subject`
    # normalization. Registry-bind happens in the finalize pass.
    wire_key_class = str(_map_lookup_str(ext, "key_class"))
    norm_key_class = "subject" if wire_key_class == "wrap" else wire_key_class

    destroyed_at = _map_lookup_timestamp(ext, "destroyed_at")

    # Step 4: `destroyed_at` MUST be ≤ host event's `authored_at`.
    # Companion OC-144 / TR-OP-109. Typed kind so the report's `tamper_kind`
    # carries `erasure_destroyed_at_after_host`.
    if destroyed_at > host_authored_at:
        raise VerifyError(
            f"erasure-evidence `destroyed_at` ({destroyed_at}) exceeds "
            f"hosting event `authored_at` ({host_authored_at}) "
            "(Companion OC-144 / ADR 0005 step 4)",
            kind="erasure_destroyed_at_after_host",
        )

    # CDDL: cascade_scopes is a non-empty array of CascadeScope text strings.
    cascade_array = _map_lookup_str(ext, "cascade_scopes")
    if not isinstance(cascade_array, list) or len(cascade_array) == 0:
        raise VerifyError(
            "erasure-evidence `cascade_scopes` MUST be a non-empty array "
            "(ADR 0005 §Wire shape)"
        )
    cascade_scopes: list[str] = []
    for scope_value in cascade_array:
        if not isinstance(scope_value, str):
            raise VerifyError("erasure-evidence cascade_scope entry is not text")
        cascade_scopes.append(scope_value)

    completion_mode = str(_map_lookup_str(ext, "completion_mode"))
    _ = str(_map_lookup_str(ext, "destruction_actor"))
    _ = str(_map_lookup_str(ext, "policy_authority"))
    _ = _map_lookup_u64(ext, "reason_code")

    # Step 3: `subject_scope` cross-field shape by `kind`.
    subject_scope = ext.get("subject_scope")
    if subject_scope is None:
        raise VerifyError("erasure-evidence `subject_scope` is missing")
    if not isinstance(subject_scope, dict):
        raise VerifyError("erasure-evidence `subject_scope` is not a map")
    subject_scope_kind = str(_map_lookup_str(subject_scope, "kind"))
    _validate_subject_scope_shape(subject_scope, subject_scope_kind)

    # Step 6: `hsm_receipt` / `hsm_receipt_kind` null-consistency.
    receipt = ext.get("hsm_receipt")
    receipt_kind = ext.get("hsm_receipt_kind")
    receipt_present = isinstance(receipt, bytes)
    receipt_kind_present = isinstance(receipt_kind, str)
    if receipt_present != receipt_kind_present:
        raise VerifyError(
            "erasure-evidence `hsm_receipt` and `hsm_receipt_kind` must "
            "both be null or both non-null (ADR 0005 step 6)"
        )

    # Step 7 (Phase-1 structural): every attestation row carries a 64-byte
    # signature and a recognized `authority_class`. Crypto-verification of
    # the Ed25519 signature itself rides Phase-2+.
    attestations = _map_lookup_str(ext, "attestations")
    if not isinstance(attestations, list) or len(attestations) == 0:
        raise VerifyError(
            "erasure-evidence `attestations` MUST be non-empty "
            "(ADR 0005 §Wire shape)"
        )
    attestation_classes: list[str] = []
    attestation_signatures_well_formed = True
    for entry in attestations:
        if not isinstance(entry, dict):
            raise VerifyError("attestation entry is not a map")
        ac = str(_map_lookup_str(entry, "authority_class"))
        attestation_classes.append(ac)
        sig = _map_lookup_str(entry, "signature")
        if not isinstance(sig, bytes) or len(sig) != 64:
            attestation_signatures_well_formed = False
        # `authority` is captured by the wire but not yet used by the
        # Phase-1 verifier (no authority↔key registry binding); we still
        # require the field per CDDL.
        _ = str(_map_lookup_str(entry, "authority"))

    return ErasureEvidenceDetails(
        evidence_id=evidence_id,
        kid_destroyed=kid_destroyed,
        norm_key_class=norm_key_class,
        destroyed_at=destroyed_at,
        cascade_scopes=cascade_scopes,
        completion_mode=completion_mode,
        attestation_signatures_well_formed=attestation_signatures_well_formed,
        attestation_classes=attestation_classes,
        subject_scope_kind=subject_scope_kind,
    )


def _decode_key_bag_recipients(payload_value: dict) -> list[bytes]:
    """Extracts wrap recipients from `payload.key_bag.entries[*].recipient`
    so step 8 (post_erasure_wrap detection) can compare against
    `kid_destroyed`. Mirrors Rust `decode_key_bag_recipients`.
    """

    key_bag = payload_value.get("key_bag")
    if key_bag is None or not isinstance(key_bag, dict):
        return []
    entries = key_bag.get("entries")
    if entries is None or not isinstance(entries, list):
        return []
    out: list[bytes] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise VerifyError("key_bag entry is not a map")
        recipient = _map_lookup_bytes(entry, "recipient")
        out.append(recipient)
    return out


def _decode_event_details(
    event: ParsedSign1,
    identity_event_type_admitted: Optional[Callable[[str], bool]] = None,
) -> EventDetails:
    if identity_event_type_admitted is None:
        identity_event_type_admitted = _is_identity_attestation_event_type
    if event.payload is None:
        raise VerifyError("detached event payloads are out of scope")
    payload_value = _decode_value(event.payload)
    if not isinstance(payload_value, dict):
        raise VerifyError("event payload root is not a map")
    scope = _map_lookup_bytes(payload_value, "ledger_scope")
    sequence = _map_lookup_u64(payload_value, "sequence")
    prev_raw = _map_lookup_optional_bytes(payload_value, "prev_hash")
    author_event_hash = _map_lookup_fixed_bytes(payload_value, "author_event_hash", 32)
    content_hash = _map_lookup_fixed_bytes(payload_value, "content_hash", 32)
    canonical_event_hash = _recompute_canonical_event_hash(scope, event.payload)

    # Core §6.1 / §17.2 — `idempotency_key` MUST be a CBOR byte string of
    # 1..=64 bytes. Length-bound violations surface as the typed §17.5
    # `idempotency_key_length_invalid` so the report's `tamper_kind`
    # localizes the structural failure (TR-CORE-158).
    idempotency_key = _map_lookup_bytes(payload_value, "idempotency_key")
    if not isinstance(idempotency_key, bytes):
        raise VerifyError(
            "idempotency_key is not a CBOR byte string",
            kind="idempotency_key_length_invalid",
        )
    if len(idempotency_key) == 0 or len(idempotency_key) > 64:
        raise VerifyError(
            f"idempotency_key length {len(idempotency_key)} outside Core §6.1 / §17.2 bound 1..=64",
            kind="idempotency_key_length_invalid",
        )

    header = _map_lookup_str(payload_value, "header")
    if not isinstance(header, dict):
        raise VerifyError("header not map")
    authored_at = _map_lookup_timestamp(header, "authored_at")
    et = _map_lookup_bytes(header, "event_type")
    cl = _map_lookup_bytes(header, "classification")
    if not isinstance(et, bytes) or not isinstance(cl, bytes):
        raise VerifyError("event_type/classification")
    event_type = et.decode("utf-8")
    classification = cl.decode("utf-8")
    pr = _map_lookup_str(payload_value, "payload_ref")
    if not isinstance(pr, dict):
        raise VerifyError("payload_ref")
    rt = pr.get("ref_type")
    if rt == "inline":
        inline = _map_lookup_bytes(pr, "ciphertext")
        external = False
    elif rt == "external":
        inline = None
        external = True
    else:
        raise VerifyError("payload_ref.ref_type unsupported")
    exts = payload_value.get("extensions")
    transition: Optional[TransitionDetails] = None
    attachment_binding: Optional[AttachmentBindingDetails] = None
    erasure: Optional[ErasureEvidenceDetails] = None
    certificate: Optional[CertificateDetails] = None
    user_content_attestation: Optional[UserContentAttestationDetails] = None
    identity_attestation_subject: Optional[str] = None
    supersedes_chain: Optional[SupersedesChainIdDetails] = None
    if isinstance(exts, dict):
        transition = _decode_transition_details(exts)
        attachment_binding = _decode_attachment_binding_details(exts)
        erasure = _decode_erasure_evidence_details(exts, authored_at)
        certificate = _decode_certificate_payload(exts)
        user_content_attestation = _decode_user_content_attestation_payload(exts, authored_at)
        identity_attestation_subject = _decode_identity_attestation_subject(
            exts, event_type, identity_event_type_admitted
        )
        supersedes_chain = _decode_supersedes_chain_id_payload(exts)
    elif exts is not None:
        raise VerifyError("extensions not map")
    wrap_recipients = _decode_key_bag_recipients(payload_value)
    return EventDetails(
        scope=scope,
        sequence=sequence,
        authored_at=authored_at,
        event_type=event_type,
        classification=classification,
        prev_hash=prev_raw,
        author_event_hash=author_event_hash,
        content_hash=content_hash,
        canonical_event_hash=canonical_event_hash,
        idempotency_key=idempotency_key,
        payload_ref_inline=inline,
        payload_ref_external=external,
        transition=transition,
        attachment_binding=attachment_binding,
        erasure=erasure,
        certificate=certificate,
        user_content_attestation=user_content_attestation,
        supersedes_chain=supersedes_chain,
        identity_attestation_subject=identity_attestation_subject,
        wrap_recipients=wrap_recipients,
    )


def _decode_supersedes_chain_id_payload(
    extensions: dict[str, Any],
) -> Optional[SupersedesChainIdDetails]:
    ext = extensions.get(SUPERSEDES_CHAIN_ID_EVENT_EXTENSION)
    if ext is None:
        return None
    if not isinstance(ext, dict):
        raise VerifyError("supersedes-chain-id extension is not a map")
    return SupersedesChainIdDetails(
        chain_id=_map_lookup_bytes(ext, "chain_id"),
        checkpoint_hash=_map_lookup_fixed_bytes(ext, "checkpoint_hash", 32),
    )


def _parse_signing_key_registry(data: bytes) -> dict[bytes, SigningKeyEntry]:
    """Backwards-compat wrapper that drops the non-signing map.

    Call sites that need to detect class-confusion attacks per Core §8.7.3
    step 4 should use ``_parse_key_registry`` directly.
    """

    signing, _non_signing = _parse_key_registry(data)
    return signing


def _parse_key_registry(
    data: bytes,
) -> tuple[dict[bytes, SigningKeyEntry], dict[bytes, NonSigningKeyEntry]]:
    """Parses the unified key registry per Core §8 (ADR 0006).

    Verifier dispatch follows Core §8.7.3 step 1: an entry whose top-level map
    carries a `kind` field is `KeyEntry` (§8.7.1); an entry without `kind` is
    the legacy `SigningKeyEntry` flat shape (§8.2). Both paths populate the
    signing-key map identically for `kind = "signing"` and the legacy shape.

    Reserved non-signing classes (`tenant-root`, `scope`, `subject`,
    `recovery`) and unknown extension `tstr` kinds are NOT inserted into the
    signing-key map — they cannot resolve a COSE_Sign1 protected-header `kid`.
    They are returned in the second map so the caller can emit
    `key_class_mismatch` (Core §8.7.3 step 4) when an event tries to sign
    under such a kid.

    Per Core §8.7.6 the wire string `"wrap"` is a deprecated synonym for
    `"subject"`; this parser normalizes the stored class label.
    """

    v = _decode_value(data)
    if not isinstance(v, list):
        raise VerifyError("signing-key registry root is not an array")

    reg: dict[bytes, SigningKeyEntry] = {}
    non_signing: dict[bytes, NonSigningKeyEntry] = {}

    for entry in v:
        if not isinstance(entry, dict):
            raise VerifyError("registry entry not map")

        # Core §8.7.3 step 1: dispatch on presence of `kind`.
        kind_raw = entry.get("kind")
        if kind_raw is not None and not isinstance(kind_raw, str):
            raise VerifyError("registry entry `kind` is not a text string")
        # Core §8.7.6: normalize legacy `"wrap"` → `"subject"`.
        kind_norm: Optional[str] = (
            "subject" if kind_raw == "wrap" else kind_raw
        )

        kid = _map_lookup_bytes(entry, "kid")

        if kind_norm is None or kind_norm == "signing":
            # Legacy `SigningKeyEntry` (no `kind`) OR new `KeyEntrySigning`.
            pubkey = _map_lookup_fixed_bytes(entry, "pubkey", 32)
            status = _map_lookup_u64(entry, "status")
            vt_raw = _map_lookup_optional_str(entry, "valid_to")
            valid_to: Optional[TrellisTimestamp]
            if vt_raw is None:
                valid_to = None
            elif isinstance(vt_raw, list) and len(vt_raw) == 2:
                if isinstance(vt_raw[0], int) and isinstance(vt_raw[1], int):
                    valid_to = TrellisTimestamp(vt_raw[0], vt_raw[1])
                else:
                    raise VerifyError("valid_to invalid")
            elif isinstance(vt_raw, int):
                raise VerifyError(
                    "legacy uint timestamp in valid_to",
                    kind="legacy_timestamp_format",
                )
            else:
                raise VerifyError("valid_to must be [uint, uint] or null")
            reg[kid] = SigningKeyEntry(
                public_key=pubkey, status=status, valid_to=valid_to
            )
        elif kind_norm in _RESERVED_NON_SIGNING_KIND:
            # Core §8.7.3 step 3: reserved non-signing class. Phase-1
            # verifier does not validate class-specific inner fields (the
            # deep validation rides Phase-2+ activation per ADR 0006), but
            # it DOES enforce the structural-shape gate of §8.7.1: the entry
            # MUST carry an `attributes` map. Absent or wrong-typed →
            # `key_entry_attributes_shape_mismatch` (TR-CORE-048). The kind
            # tag on the resulting VerifyError is consumed by
            # verify_tampered_ledger / verify_export_zip so the report's
            # tamper_kind carries the structural-failure code.
            attrs = entry.get("attributes")
            if not isinstance(attrs, dict):
                raise VerifyError(
                    "key_entry_attributes_shape_mismatch: KeyEntry of "
                    f"kind=\"{kind_norm}\" missing required `attributes` map "
                    "(Core §8.7.1)",
                    kind="key_entry_attributes_shape_mismatch",
                )
            # Subject-class capture: read `valid_to` from `attributes` for
            # forward-compatible Phase-2+ enforcement (ADR 0006 *Phase-1
            # runtime discipline*). Other classes don't carry valid_to.
            subject_valid_to: Optional[TrellisTimestamp] = None
            if kind_norm == "subject":
                vt = attrs.get("valid_to")
                if vt is None:
                    subject_valid_to = None
                elif isinstance(vt, list) and len(vt) == 2:
                    if isinstance(vt[0], int) and isinstance(vt[1], int):
                        subject_valid_to = TrellisTimestamp(vt[0], vt[1])
                    else:
                        raise VerifyError(
                            "key_entry_attributes_shape_mismatch: subject "
                            "`valid_to` array elements must be uint (Core §8.7.2)",
                            kind="key_entry_attributes_shape_mismatch",
                        )
                elif isinstance(vt, int):
                    raise VerifyError(
                        "legacy uint timestamp in subject valid_to",
                        kind="legacy_timestamp_format",
                    )
                else:
                    raise VerifyError(
                        "key_entry_attributes_shape_mismatch: subject "
                        "`valid_to` is neither [uint, uint] nor null (Core §8.7.2)",
                        kind="key_entry_attributes_shape_mismatch",
                    )
            non_signing[kid] = NonSigningKeyEntry(
                class_=kind_norm, subject_valid_to=subject_valid_to,
            )
        else:
            # Core §8.7.3 step 4 *Unknown `kind`*: forward-compatibility floor.
            non_signing[kid] = NonSigningKeyEntry(class_=kind_norm)

    return reg, non_signing


def _parse_bound_registry(data: bytes) -> BoundRegistry:
    v = _decode_value(data)
    if not isinstance(v, dict):
        raise VerifyError("bound registry root is not a map")
    et = _map_lookup_str(v, "event_types")
    if not isinstance(et, dict):
        raise VerifyError("event_types")
    event_types = [str(k) for k in et.keys() if isinstance(k, str)]
    cl_arr = _map_lookup_str(v, "classifications")
    if not isinstance(cl_arr, list):
        raise VerifyError("classifications")
    classifications = [str(x) for x in cl_arr if isinstance(x, str)]
    return BoundRegistry(event_types=event_types, classifications=classifications)


def _event_identity(event: ParsedSign1) -> tuple[bytes, bytes]:
    d = _decode_event_details(event)
    return d.scope, d.canonical_event_hash


def _parse_custody_model(data: bytes) -> str:
    v = _decode_value(data)
    if not isinstance(v, dict):
        raise VerifyError("posture declaration root is not a map")
    cm = _map_lookup_str(v, "custody_model")
    if not isinstance(cm, dict):
        raise VerifyError("custody_model")
    return str(_map_lookup_str(cm, "custody_model_id"))


def _parse_disclosure_profile(data: bytes) -> str:
    v = _decode_value(data)
    if not isinstance(v, dict):
        raise VerifyError("posture declaration root is not a map")
    return str(_map_lookup_str(v, "disclosure_profile"))


def _custody_rank(value: str) -> int:
    return {"CM-A": 3, "CM-B": 2, "CM-C": 1}.get(value, 0)


def _requires_dual_attestation(from_state: str, to_state: str) -> bool:
    return _custody_rank(to_state) > _custody_rank(from_state)


def _finalize_erasure_evidence(
    payloads: list[tuple[int, ErasureEvidenceDetails, bytes]],
    chain: list["_ChainEventSummary"],
    registry: dict[bytes, SigningKeyEntry],
    non_signing_registry: Optional[dict[bytes, NonSigningKeyEntry]],
    event_failures: list[VerificationFailure],
) -> list[ErasureEvidenceOutcome]:
    """ADR 0005 §"Verifier obligations" finalization pass: runs steps 2 / 5 /
    7 / 8 / 10 after every event has been decoded. Mirrors Rust
    `finalize_erasure_evidence` byte-for-byte.

    Localizable failures are pushed into `event_failures` so the report's
    `tamper_kind` projection picks them up. Cross-payload group failures
    localize to the second-emitted payload's canonical hash.
    """

    if not payloads:
        return []

    # Step 5 / 8 group state — keyed by `kid_destroyed` bytes.
    group_destroyed_at: dict[bytes, int] = {}
    group_key_class: dict[bytes, str] = {}
    group_conflict_destroyed_at: set[bytes] = set()
    group_conflict_key_class: set[bytes] = set()
    outcomes: list[ErasureEvidenceOutcome] = []

    # First pass: step 2 (registry bind) per payload + step 5 (group
    # destroyed_at / key_class agreement).
    for index, payload, canonical_hash in payloads:
        # Step 2: registry bind. If `kid_destroyed` resolves to exactly one
        # KeyEntry row, `norm_key_class` MUST match that row's `kind`. For
        # legacy flat `SigningKeyEntry` (no `kind`), expected = `signing`.
        registry_class: Optional[str] = None
        if payload.kid_destroyed in registry:
            registry_class = "signing"
        elif non_signing_registry is not None and payload.kid_destroyed in non_signing_registry:
            registry_class = non_signing_registry[payload.kid_destroyed].class_

        if registry_class is not None and registry_class != payload.norm_key_class:
            event_failures.append(
                VerificationFailure(
                    "erasure_key_class_registry_mismatch",
                    _hex(canonical_hash),
                )
            )

        # Step 5: group by kid_destroyed.
        if payload.kid_destroyed not in group_destroyed_at:
            group_destroyed_at[payload.kid_destroyed] = payload.destroyed_at
        else:
            if (
                group_destroyed_at[payload.kid_destroyed] != payload.destroyed_at
                and payload.kid_destroyed not in group_conflict_destroyed_at
            ):
                event_failures.append(
                    VerificationFailure(
                        "erasure_destroyed_at_conflict",
                        _hex(canonical_hash),
                    )
                )
                group_conflict_destroyed_at.add(payload.kid_destroyed)
        if payload.kid_destroyed not in group_key_class:
            group_key_class[payload.kid_destroyed] = payload.norm_key_class
        else:
            if (
                group_key_class[payload.kid_destroyed] != payload.norm_key_class
                and payload.kid_destroyed not in group_conflict_key_class
            ):
                event_failures.append(
                    VerificationFailure(
                        "erasure_key_class_payload_conflict",
                        _hex(canonical_hash),
                    )
                )
                group_conflict_key_class.add(payload.kid_destroyed)

        outcomes.append(
            ErasureEvidenceOutcome(
                evidence_id=payload.evidence_id,
                kid_destroyed=payload.kid_destroyed,
                destroyed_at=payload.destroyed_at,
                cascade_scopes=list(payload.cascade_scopes),
                completion_mode=payload.completion_mode,
                event_index=index,
                signature_verified=payload.attestation_signatures_well_formed,
                post_erasure_uses=0,
                post_erasure_wraps=0,
                cascade_violations=[],
                failures=[],
            )
        )

    # Step 8: chain consistency for `norm_key_class ∈ {"signing", "subject"}`.
    for outcome in outcomes:
        if outcome.kid_destroyed in group_conflict_destroyed_at:
            outcome.failures.append("erasure_destroyed_at_conflict")
            continue
        if outcome.kid_destroyed in group_conflict_key_class:
            outcome.failures.append("erasure_key_class_payload_conflict")
            continue
        cls = group_key_class.get(outcome.kid_destroyed, "")
        if cls not in ("signing", "subject"):
            # ADR 0005 step 8 Phase-1 scope: only signing + subject classes
            # run the chain walk. Other classes are wire-valid; subtree
            # dispatch co-lands with ADR 0006 follow-on milestones.
            continue
        destroyed_at = group_destroyed_at.get(outcome.kid_destroyed)
        if destroyed_at is None:
            continue
        for ev in chain:
            if ev.authored_at <= destroyed_at:
                continue
            if ev.signing_kid == outcome.kid_destroyed:
                outcome.post_erasure_uses += 1
                outcome.failures.append("post_erasure_use")
                event_failures.append(
                    VerificationFailure(
                        "post_erasure_use",
                        _hex(ev.canonical_event_hash),
                    )
                )
            if any(r == outcome.kid_destroyed for r in ev.wrap_recipients):
                outcome.post_erasure_wraps += 1
                outcome.failures.append("post_erasure_wrap")
                event_failures.append(
                    VerificationFailure(
                        "post_erasure_wrap",
                        _hex(ev.canonical_event_hash),
                    )
                )

    # Step 7 (Phase-1 structural): malformed attestation surfaces as a
    # localized failure so `integrity_verified` flips and the `tamper_kind`
    # projection finds it.
    for outcome in outcomes:
        if not outcome.signature_verified:
            event_failures.append(
                VerificationFailure(
                    "erasure_attestation_signature_invalid",
                    _hex(b"\x00" * 32),
                )
            )

    return outcomes


def _affirmation_payload_bytes(
    target: EventDetails, payload_blobs: Optional[dict[bytes, bytes]]
) -> Optional[bytes]:
    """Inline kernel bytes, or external bytes from `payload_blobs` keyed by
    `content_hash` (mirrors Rust `affirmation_payload_cow`). When
    `payload_blobs` is absent, external rows are not resolvable in steps 2 / 7."""
    if target.payload_ref_inline is not None:
        return target.payload_ref_inline
    if target.payload_ref_external and payload_blobs is not None:
        return payload_blobs.get(target.content_hash)
    return None


def _finalize_certificates_of_completion(
    payloads: list[tuple[int, CertificateDetails, bytes]],
    events: list[ParsedSign1],
    event_failures: list[VerificationFailure],
    payload_blobs: Optional[dict[bytes, bytes]] = None,
    resolver: Optional[ResponseProofResolver] = None,
) -> list[CertificateOfCompletionOutcome]:
    """ADR 0007 §"Verifier obligations" cross-event finalization. Step 1
    runs in `_decode_certificate_payload`; this pass runs steps 2 (id
    collision), 5 (signing-event resolution), 6 (timestamp equivalence),
    7 (response_ref equivalence), and 8 (outcome accumulation). Mirrors
    Rust `finalize_certificates_of_completion` byte-for-byte.

    **Phase-1 chain-context posture.** Steps 5 / 6 / 7 require the full
    event list to resolve `signing_events[i]` digests against in-chain
    SignatureAffirmation events. The genesis-append paths
    (`verify_single_event` / `verify_tampered_ledger`) frequently pass a
    minimal `events` slice; in that case `signing_event_unresolved` would
    false-positive on vectors whose contract is "this one event decodes".
    Posture: when an event in `events` matches a `signing_events[i]`
    digest, run the cross checks. Step 4 (attachment lineage) is wholly
    deferred to `_verify_certificate_attachment_lineage` (export-bundle
    path)."""
    if not payloads:
        return []

    if resolver is None:
        resolver = _NoopResponseProofResolver()

    # Build canonical_event_hash → EventDetails lookup once for steps 5/6/7.
    event_by_hash: dict[bytes, EventDetails] = {}
    for event in events:
        try:
            details = _decode_event_details(event)
        except VerifyError:
            continue
        if details.canonical_event_hash not in event_by_hash:
            event_by_hash[details.canonical_event_hash] = details

    # Step 2 second sub-clause: certificate_id collision detection.
    # "Differ" is canonical-payload disagreement; for the Phase-1 reference
    # verifier we compare (content_hash, signing_events, signer_count,
    # completed_at, workflow_status) — the load-bearing fields ADR 0007
    # §"Field semantics" identifies as collision-indicative.
    id_to_canonical: dict[str, CertificateDetails] = {}
    id_collision_reported: set[str] = set()
    for _index, payload, canonical_hash in payloads:
        if payload.certificate_id not in id_to_canonical:
            id_to_canonical[payload.certificate_id] = payload
            continue
        prior = id_to_canonical[payload.certificate_id]
        differs = (
            prior.presentation_artifact.content_hash
            != payload.presentation_artifact.content_hash
            or prior.signing_events != payload.signing_events
            or prior.chain_summary.signer_count != payload.chain_summary.signer_count
            or prior.completed_at != payload.completed_at
            or prior.chain_summary.workflow_status
            != payload.chain_summary.workflow_status
        )
        if differs and payload.certificate_id not in id_collision_reported:
            id_collision_reported.add(payload.certificate_id)
            event_failures.append(
                VerificationFailure("certificate_id_collision", _hex(canonical_hash))
            )

    outcomes: list[CertificateOfCompletionOutcome] = []
    for index, payload, canonical_hash in payloads:
        outcome = CertificateOfCompletionOutcome(
            certificate_id=payload.certificate_id,
            event_index=index,
            completed_at=payload.completed_at,
            signer_count=payload.chain_summary.signer_count,
            # Step 4 (attachment lineage + content recompute) is the
            # export-bundle path's responsibility. Genesis-append context:
            # mark `attachment_resolved = true` so the §19 step-9 fold
            # doesn't false-positive on minimal-genesis fixtures.
            attachment_resolved=True,
            all_signing_events_resolved=True,
            chain_summary_consistent=True,
            failures=[],
        )

        # Step 3 (Phase-1 structural attestation contract).
        if not payload.attestation_signatures_well_formed:
            outcome.chain_summary_consistent = False
            outcome.failures.append("attestation_insufficient")
            event_failures.append(
                VerificationFailure("attestation_insufficient", _hex(canonical_hash))
            )

        # Steps 5 / 6 / 7 — each `signing_events[i]` digest cross-checked.
        for i, signing_event_hash in enumerate(payload.signing_events):
            target = event_by_hash.get(signing_event_hash)
            if target is None:
                outcome.all_signing_events_resolved = False
                outcome.failures.append("signing_event_unresolved")
                event_failures.append(
                    VerificationFailure(
                        "signing_event_unresolved", _hex(signing_event_hash)
                    )
                )
                continue
            display = payload.chain_summary.signer_display[i]
            if display.signed_at != target.authored_at:
                outcome.chain_summary_consistent = False
                outcome.failures.append("signing_event_timestamp_mismatch")
                event_failures.append(
                    VerificationFailure(
                        "signing_event_timestamp_mismatch", _hex(signing_event_hash)
                    )
                )

        # Step 7 — response_ref equivalence when non-null.
        # Trellis Core does NOT inspect WOS/Formspec field names. The
        # resolver (`WosFormspecResolver` in `verify_wos.py`) is the only
        # code path allowed to read consumer-domain field names; Core only
        # compares the returned hash against `response_ref`.
        if payload.chain_summary.response_ref is not None:
            response_ref = payload.chain_summary.response_ref
            had_resolvable_response = False
            matched = False
            for signing_event_hash in payload.signing_events:
                target = event_by_hash.get(signing_event_hash)
                if target is None:
                    continue
                affirmation = _affirmation_payload_bytes(target, payload_blobs)
                if affirmation is None:
                    continue
                try:
                    proof = resolver.resolve(affirmation)
                except MalformedResponseDigestError:
                    # Phase M leaves this as `continue` to preserve current
                    # behavior. Phase N flips this to a fail-closed
                    # `response_ref_mismatch` (or a more-specific tamper
                    # kind on the resolver-implementation side).
                    continue
                if proof is None:
                    continue
                had_resolvable_response = True
                if proof.response_hash == response_ref:
                    matched = True
                    break
            if had_resolvable_response and not matched:
                outcome.chain_summary_consistent = False
                outcome.failures.append("response_ref_mismatch")
                event_failures.append(
                    VerificationFailure("response_ref_mismatch", _hex(canonical_hash))
                )

        # Step 2 first sub-clause (per-index principal_ref equivalence).
        # Resolver returns the consumer-domain principal-ref string when it
        # recognizes the payload; Core only compares against
        # `display.principal_ref`.
        for i, signing_event_hash in enumerate(payload.signing_events):
            target = event_by_hash.get(signing_event_hash)
            if target is None:
                continue
            affirmation = _affirmation_payload_bytes(target, payload_blobs)
            if affirmation is None:
                continue
            principal_ref = resolver.resolve_principal_ref(affirmation)
            if principal_ref is None:
                continue
            display = payload.chain_summary.signer_display[i]
            if display.principal_ref != principal_ref:
                outcome.chain_summary_consistent = False
                outcome.failures.append("certificate_chain_summary_mismatch")
                event_failures.append(
                    VerificationFailure(
                        "certificate_chain_summary_mismatch", _hex(canonical_hash)
                    )
                )
                break

        outcomes.append(outcome)

    return outcomes


def _is_syntactically_valid_uri(value: str) -> bool:
    """ADR 0010 §"Verifier obligations" step 2 `signing_intent` check.
    Trellis verifies syntactic URI validity per RFC 3986 only; semantic
    validity (legal-effect class registry membership) lives at the WOS
    Signature Profile + jurisdiction registry layer. Mirrors Rust
    `is_syntactically_valid_uri`."""
    sep = value.find(":")
    if sep <= 0 or sep == len(value) - 1:
        return False
    scheme = value[:sep]
    rest = value[sep + 1 :]
    if not scheme or not rest:
        return False
    if not scheme[0].isascii() or not scheme[0].isalpha():
        return False
    for ch in scheme[1:]:
        if not (ch.isascii() and (ch.isalnum() or ch in "+-.")):
            return False
    return True


def _is_operator_uri(value: str) -> bool:
    """Companion §6.4 operator-URI prefix check used for ADR 0010 step 8
    (`user_content_attestation_operator_in_user_slot`). Phase-1 baseline;
    deployments substitute or extend via deployment-local lint. Mirrors Rust
    `is_operator_uri`."""
    return value.startswith(OPERATOR_URI_PREFIX_TRELLIS) or value.startswith(
        OPERATOR_URI_PREFIX_WOS
    )


def _is_identity_attestation_event_type(event_type: str) -> bool:
    """ADR 0010 step 4 admit list.

    Admits the §6.7 + §10.6 reserved test prefix. Consumer-owned identity
    taxonomies are admitted through composed verifier hooks. Mirrors Rust
    `is_identity_attestation_event_type`.
    """
    return event_type == PHASE_1_TEST_IDENTITY_EVENT_TYPE


def _decode_identity_attestation_subject(
    exts: dict,
    event_type: str,
    identity_event_type_admitted: Callable[[str], bool] = _is_identity_attestation_event_type,
) -> Optional[str]:
    """Resolves the subject of an identity-attestation event from its
    decoded `EventPayload.extensions` map. Convention:
    `extensions[event_type]["subject"]` carries the principal URI.
    Returns `None` for non-identity events or for identity events whose
    payload omits the subject field. Mirrors Rust
    `decode_identity_attestation_subject`."""
    if not _is_identity_attestation_event_type(event_type) and not identity_event_type_admitted(
        event_type
    ):
        return None
    ext = exts.get(event_type)
    if not isinstance(ext, dict):
        return None
    subject = ext.get("subject")
    return subject if isinstance(subject, str) else None


def _parse_admit_unverified_user_attestations(declaration_bytes: bytes) -> bool:
    """Reads `admit_unverified_user_attestations` from a Posture Declaration
    decoded as a dCBOR map. Default `false` per ADR 0010 §"Field semantics"
    `identity_attestation_ref` clause — failing-closed to default-required.
    Mirrors Rust `parse_admit_unverified_user_attestations`."""
    try:
        value = cbor2.loads(declaration_bytes)
    except CBORDecodeError:
        # Malformed posture CBOR → fail-closed (treat as absent / false).
        return False
    if not isinstance(value, dict):
        return False
    field_value = value.get("admit_unverified_user_attestations")
    return field_value is True


def _compute_user_content_attestation_preimage(
    attestation_id: str,
    attested_event_hash: bytes,
    attested_event_position: int,
    attestor: str,
    identity_attestation_ref: Optional[bytes],
    signing_intent: str,
    attested_at: TrellisTimestamp,
) -> bytes:
    """Builds the dCBOR signature preimage for a user-content attestation
    per ADR 0010 §"Wire shape": `dCBOR([attestation_id,
    attested_event_hash, attested_event_position, attestor,
    identity_attestation_ref, signing_intent, attested_at])`. Mirrors Rust
    `compute_user_content_attestation_preimage`."""
    return cbor2.dumps(
        [
            attestation_id,
            attested_event_hash,
            attested_event_position,
            attestor,
            identity_attestation_ref,  # bytes or None
            signing_intent,
            [attested_at.seconds, attested_at.nanos],
        ],
        canonical=True,
    )


def _decode_user_content_attestation_payload(
    exts: dict, host_authored_at: TrellisTimestamp
) -> Optional[UserContentAttestationDetails]:
    """Decodes the optional `trellis.user-content-attestation.v1` extension
    payload. Step 1 (CDDL decode) bubbles structural failures via
    `VerifyError`. Step 2 (intra-payload invariants — `attested_at ==
    host_authored_at`; `signing_intent` is a syntactically valid URI per
    RFC 3986) is recorded as a deferred `step_2_failure` marker per ADR 0010
    §"Verifier obligations" step 2 (these failures flip
    `integrity_verified = false` only — they are NOT structure failures).
    `_finalize_user_content_attestations` raises the marker as an
    `event_failure`. Mirrors Rust
    `decode_user_content_attestation_payload`."""
    ext = exts.get(USER_CONTENT_ATTESTATION_EVENT_EXTENSION)
    if ext is None:
        return None
    if not isinstance(ext, dict):
        raise VerifyError("user-content-attestation extension is not a map")

    attestation_id = str(_map_lookup_str(ext, "attestation_id"))
    attested_event_hash = _map_lookup_fixed_bytes(ext, "attested_event_hash", 32)
    attested_event_position = _map_lookup_u64(ext, "attested_event_position")
    attestor = str(_map_lookup_str(ext, "attestor"))
    identity_attestation_ref = _map_lookup_optional_fixed_bytes(
        ext, "identity_attestation_ref", 32
    )
    signing_intent = str(_map_lookup_str(ext, "signing_intent"))
    attested_at = _map_lookup_timestamp(ext, "attested_at")
    signature = _map_lookup_fixed_bytes(ext, "signature", 64)
    signing_kid = _map_lookup_fixed_bytes(ext, "signing_kid", 16)

    # Step 2 — intra-payload invariants. Deferred-marker pattern preserves
    # ADR 0010 §"Verifier obligations" step 2 prose (`integrity_verified`
    # only; NOT a structure failure). First-detected wins.
    if attested_at != host_authored_at:
        step_2_failure: Optional[str] = "user_content_attestation_timestamp_mismatch"
    elif not _is_syntactically_valid_uri(signing_intent):
        step_2_failure = "user_content_attestation_intent_malformed"
    else:
        step_2_failure = None

    canonical_preimage = _compute_user_content_attestation_preimage(
        attestation_id,
        attested_event_hash,
        attested_event_position,
        attestor,
        identity_attestation_ref,
        signing_intent,
        attested_at,
    )

    return UserContentAttestationDetails(
        attestation_id=attestation_id,
        attested_event_hash=attested_event_hash,
        attested_event_position=attested_event_position,
        attestor=attestor,
        identity_attestation_ref=identity_attestation_ref,
        signing_intent=signing_intent,
        attested_at=attested_at,
        signature=signature,
        signing_kid=signing_kid,
        canonical_preimage=canonical_preimage,
        step_2_failure=step_2_failure,
    )


def _verify_user_content_attestation_signature(
    details: UserContentAttestationDetails, public_key: bytes
) -> bool:
    """ADR 0010 §"Verifier obligations" step 5. Re-hashes the pre-computed
    `canonical_preimage` under domain tag
    `trellis-user-content-attestation-v1` (Core §9.8) and verifies under the
    public key resolved from `signing_kid`. Mirrors Rust
    `verify_user_content_attestation_signature`."""
    signed_hash = domain_separated_sha256(
        USER_CONTENT_ATTESTATION_DOMAIN, details.canonical_preimage
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(details.signature, signed_hash)
    except Exception:
        return False
    return True


def _finalize_user_content_attestations(
    payloads: list[tuple[int, UserContentAttestationDetails, bytes]],
    events: list[EventDetails],
    registry: dict[bytes, SigningKeyEntry],
    posture_declaration: Optional[bytes],
    identity_event_type_admitted: Callable[[str], bool],
    event_failures: list[VerificationFailure],
) -> list[UserContentAttestationOutcome]:
    """ADR 0010 §"Verifier obligations" cross-event finalization. Step 1 +
    step 2 partial run in `_decode_user_content_attestation_payload`; this
    pass runs steps 3 (chain-position resolution), 4 (identity resolution),
    5 (signature verification), 6 (key-state check), 7 (collision
    detection), 8 (operator-in-user-slot), and 9 (outcome accumulation).
    Mirrors Rust `finalize_user_content_attestations`."""
    if not payloads:
        return []

    # Build chain lookups.
    event_by_hash: dict[bytes, EventDetails] = {}
    event_by_position: dict[tuple[bytes, int], EventDetails] = {}
    for ev in events:
        event_by_hash.setdefault(ev.canonical_event_hash, ev)
        event_by_position.setdefault((ev.scope, ev.sequence), ev)

    admit_unverified = (
        _parse_admit_unverified_user_attestations(posture_declaration)
        if posture_declaration is not None
        else False
    )

    # Step 7 collision detection.
    id_to_canonical: dict[str, UserContentAttestationDetails] = {}
    id_collision_reported: set[str] = set()
    for _index, payload, canonical_hash in payloads:
        prior = id_to_canonical.get(payload.attestation_id)
        if prior is None:
            id_to_canonical[payload.attestation_id] = payload
        else:
            differs = (
                prior.attested_event_hash != payload.attested_event_hash
                or prior.attested_event_position != payload.attested_event_position
                or prior.attestor != payload.attestor
                or prior.identity_attestation_ref != payload.identity_attestation_ref
                or prior.signing_intent != payload.signing_intent
                or prior.attested_at != payload.attested_at
            )
            if differs and payload.attestation_id not in id_collision_reported:
                id_collision_reported.add(payload.attestation_id)
                event_failures.append(
                    VerificationFailure(
                        "user_content_attestation_id_collision", _hex(canonical_hash)
                    )
                )

    outcomes: list[UserContentAttestationOutcome] = []
    for index, payload, canonical_hash in payloads:
        outcome = UserContentAttestationOutcome(
            attestation_id=payload.attestation_id,
            attested_event_hash=payload.attested_event_hash,
            attestor=payload.attestor,
            signing_intent=payload.signing_intent,
            event_index=index,
        )

        # Step 2 deferred-failure surface.
        if payload.step_2_failure is not None:
            outcome.failures.append(payload.step_2_failure)
            event_failures.append(
                VerificationFailure(payload.step_2_failure, _hex(canonical_hash))
            )
            outcomes.append(outcome)
            continue

        # Step 8 — operator-in-user-slot.
        if _is_operator_uri(payload.attestor):
            outcome.failures.append("user_content_attestation_operator_in_user_slot")
            event_failures.append(
                VerificationFailure(
                    "user_content_attestation_operator_in_user_slot",
                    _hex(canonical_hash),
                )
            )

        # Step 3 — chain-position resolution.
        attestation_event = event_by_hash.get(canonical_hash)
        attestation_scope = attestation_event.scope if attestation_event else b""
        host = event_by_position.get((attestation_scope, payload.attested_event_position))
        if host is None or host.canonical_event_hash != payload.attested_event_hash:
            outcome.chain_position_resolved = False
            outcome.failures.append("user_content_attestation_chain_position_mismatch")
            event_failures.append(
                VerificationFailure(
                    "user_content_attestation_chain_position_mismatch",
                    _hex(canonical_hash),
                )
            )

        # Step 4 — identity resolution. Failure-location convention follows
        # the Rust verifier: identity-related failures use the
        # `identity_attestation_ref` digest as `failing_event_id` (the
        # unresolvable / wrong-subject / temporally-inverted target),
        # NOT the UCA event's canonical hash.
        if payload.identity_attestation_ref is not None:
            identity_ref = payload.identity_attestation_ref
            identity_event = event_by_hash.get(identity_ref)
            identity_type_admitted = (
                identity_event is not None
                and (
                    _is_identity_attestation_event_type(identity_event.event_type)
                    or identity_event_type_admitted(identity_event.event_type)
                )
            )
            if (
                identity_event is None
                or not identity_type_admitted
                or identity_event.scope != attestation_scope
            ):
                outcome.identity_resolved = False
                outcome.failures.append("user_content_attestation_identity_unresolved")
                event_failures.append(
                    VerificationFailure(
                        "user_content_attestation_identity_unresolved",
                        _hex(identity_ref),
                    )
                )
            elif identity_event.sequence >= payload.attested_event_position:
                outcome.identity_resolved = False
                outcome.failures.append(
                    "user_content_attestation_identity_temporal_inversion"
                )
                event_failures.append(
                    VerificationFailure(
                        "user_content_attestation_identity_temporal_inversion",
                        _hex(identity_ref),
                    )
                )
            elif identity_event.identity_attestation_subject != payload.attestor:
                outcome.identity_resolved = False
                outcome.failures.append(
                    "user_content_attestation_identity_subject_mismatch"
                )
                event_failures.append(
                    VerificationFailure(
                        "user_content_attestation_identity_subject_mismatch",
                        _hex(identity_ref),
                    )
                )
        else:
            if not admit_unverified:
                outcome.identity_resolved = False
                outcome.failures.append("user_content_attestation_identity_required")
                event_failures.append(
                    VerificationFailure(
                        "user_content_attestation_identity_required",
                        _hex(canonical_hash),
                    )
                )

        # Step 6 — key-state check (precedes step 5 so a Retired/Revoked kid
        # doesn't get a `signature_invalid` mask). Only `Active` (status 0)
        # admitted in Phase-1; rotation grace lands with TODO item #5.
        key_entry = registry.get(payload.signing_kid)
        if key_entry is None or key_entry.status != 0:
            outcome.key_active = False
            outcome.failures.append("user_content_attestation_key_not_active")
            event_failures.append(
                VerificationFailure(
                    "user_content_attestation_key_not_active", _hex(canonical_hash)
                )
            )
        else:
            # Step 5 — signature verification.
            if not _verify_user_content_attestation_signature(payload, key_entry.public_key):
                outcome.signature_verified = False
                outcome.failures.append("user_content_attestation_signature_invalid")
                event_failures.append(
                    VerificationFailure(
                        "user_content_attestation_signature_invalid",
                        _hex(canonical_hash),
                    )
                )

        outcomes.append(outcome)

    return outcomes


def _verify_event_set(
    events: list[ParsedSign1],
    registry: dict[bytes, SigningKeyEntry],
    initial_posture_declaration: Optional[bytes],
    posture_declaration: Optional[bytes],
    classify_tamper: bool,
    expected_ledger_scope: Optional[bytes],
    payload_blobs: Optional[dict[bytes, bytes]],
    non_signing_registry: Optional[dict[bytes, NonSigningKeyEntry]] = None,
    identity_event_type_admitted: Callable[[str], bool] = _is_identity_attestation_event_type,
    resolver: Optional[ResponseProofResolver] = None,
) -> VerificationReport:
    event_failures: list[VerificationFailure] = []
    posture_transitions: list[PostureTransitionOutcome] = []
    erasure_payloads: list[tuple[int, ErasureEvidenceDetails, bytes]] = []
    certificate_payloads: list[tuple[int, CertificateDetails, bytes]] = []
    user_content_attestation_payloads: list[
        tuple[int, UserContentAttestationDetails, bytes]
    ] = []
    decoded_events_for_uca: list[EventDetails] = []
    chain_summaries: list[_ChainEventSummary] = []
    previous_hash: Optional[bytes] = None
    previous_authored_at: Optional[TrellisTimestamp] = None
    skip_prev = initial_posture_declaration is not None and len(events) == 1

    # Core §17.3 — Track every (ledger_scope, idempotency_key) identity seen
    # so far in this event set, mapped to the first canonical event's
    # canonical_event_hash. A second event sharing the identity with a
    # divergent canonical_event_hash is a §17.3 clause-3 violation surfaced
    # as `idempotency_key_payload_mismatch` (§17.5 + TR-CORE-160). Offline
    # check (Core §16); no Canonical Append Service state is required.
    idempotency_index: dict[tuple[bytes, bytes], bytes] = {}
    shadow_custody_model: Optional[str] = None
    shadow_disclosure_profile: Optional[str] = None
    if initial_posture_declaration is not None:
        try:
            shadow_custody_model = _parse_custody_model(initial_posture_declaration)
        except VerifyError:
            shadow_custody_model = None
        try:
            shadow_disclosure_profile = _parse_disclosure_profile(initial_posture_declaration)
        except VerifyError:
            shadow_disclosure_profile = None

    suite_i = SUITE_ID_PHASE_1

    for index, event in enumerate(events):
        key_entry = registry.get(event.kid)
        if key_entry is None:
            # Core §8.7.3 step 4: a kid resolving to a reserved non-signing
            # class fails with `key_class_mismatch` rather than the generic
            # unresolvable-kid path. Recovery-only / tenant-root / scope /
            # subject kids signing canonical events is the canonical
            # class-confusion attack.
            if non_signing_registry is not None:
                ns_entry = non_signing_registry.get(event.kid)
                if ns_entry is not None:
                    return VerificationReport.fatal(
                        "key_class_mismatch",
                        (
                            f"event signed under a `{ns_entry.class_}`-class "
                            "kid; only `signing` keys may sign canonical events "
                            "(Core §8.7.3 step 4)"
                        ),
                    )
            return VerificationReport.fatal(
                "unresolvable_manifest_kid",
                "event kid is not resolvable via the provided signing-key registry",
            )
        if event.alg != ALG_EDDSA or event.suite_id != suite_i:
            return VerificationReport.fatal(
                "unsupported_suite",
                "event protected header does not match the Trellis Phase-1 suite",
            )
        if not _verify_signature(event, key_entry.public_key):
            try:
                loc = _hex(_event_identity(event)[1])
            except Exception:  # noqa: BLE001
                loc = f"event[{index}]"
            event_failures.append(VerificationFailure("signature_invalid", loc))
            continue

        try:
            details = _decode_event_details(event, identity_event_type_admitted)
        except VerifyError as exc:
            # Surface typed structural-failure kinds (e.g.
            # `erasure_destroyed_at_after_host` from ADR 0005 step 4)
            # as the report's `tamper_kind`. Untyped decode errors
            # continue to land as generic `malformed_cose`.
            tamper_kind = exc.kind or "malformed_cose"
            warning = (
                str(exc) if exc.kind is not None
                else "event payload does not decode as a canonical Trellis event"
            )
            return VerificationReport.fatal(tamper_kind, warning)

        if key_entry.status == 3:
            if key_entry.valid_to is None:
                return VerificationReport.fatal(
                    "signing_key_registry_invalid",
                    "revoked signing-key registry entry is missing valid_to",
                )
            if details.authored_at > key_entry.valid_to:
                event_failures.append(
                    VerificationFailure("revoked_authority", _hex(details.canonical_event_hash))
                )

        if expected_ledger_scope is not None and details.scope != expected_ledger_scope:
            event_failures.append(
                VerificationFailure("scope_mismatch", _hex(details.canonical_event_hash))
            )

        # Core §17.3 clause 3 + §17.5 — duplicate (scope, idempotency_key)
        # identity with divergent canonical material is
        # `idempotency_key_payload_mismatch`. The first occurrence is admitted
        # as the canonical reference; the second occurrence is the failing
        # event. Identity is (scope, idempotency_key); divergence is by
        # canonical_event_hash (which transitively binds content_hash +
        # author_event_hash via §9.2 / §9.5 preimages). TR-CORE-160 + TR-CORE-162.
        identity_key = (details.scope, details.idempotency_key)
        prior_hash = idempotency_index.get(identity_key)
        if prior_hash is not None and prior_hash != details.canonical_event_hash:
            event_failures.append(
                VerificationFailure(
                    "idempotency_key_payload_mismatch",
                    _hex(details.canonical_event_hash),
                )
            )
        elif prior_hash is None:
            idempotency_index[identity_key] = details.canonical_event_hash
        # prior_hash is not None and equal canonical_event_hash → §17.3
        # clause 1 / clause 2 byte-equal no-op; Phase 1 ledgers SHOULD NOT
        # carry duplicate entries but byte-equal duplicates are not tampers.

        if details.payload_ref_inline is not None:
            expected_ch = domain_separated_sha256(CONTENT_DOMAIN, details.payload_ref_inline)
            if expected_ch != details.content_hash:
                event_failures.append(
                    VerificationFailure("content_hash_mismatch", _hex(details.canonical_event_hash))
                )
        elif details.payload_ref_external:
            if payload_blobs is not None:
                pb = payload_blobs.get(details.content_hash)
                if pb is not None:
                    expected_ch = domain_separated_sha256(CONTENT_DOMAIN, pb)
                    if expected_ch != details.content_hash:
                        event_failures.append(
                            VerificationFailure(
                                "content_hash_mismatch", _hex(details.canonical_event_hash)
                            )
                        )

        payload_bytes = event.payload
        assert payload_bytes is not None
        rah = _recompute_author_event_hash(payload_bytes)
        if rah is None:
            event_failures.append(
                VerificationFailure("author_preimage_invalid", _hex(details.canonical_event_hash))
            )
        elif rah != details.author_event_hash:
            event_failures.append(
                VerificationFailure("hash_mismatch", _hex(details.canonical_event_hash))
            )

        if skip_prev:
            pass
        elif details.sequence == 0:
            if details.prev_hash is not None:
                kind = "event_reorder" if classify_tamper else "prev_hash_mismatch"
                event_failures.append(VerificationFailure(kind, _hex(details.canonical_event_hash)))
        elif previous_hash != details.prev_hash:
            if classify_tamper:
                if previous_hash is None and len(events) == 1:
                    kind = "event_truncation"
                elif previous_hash is None:
                    kind = "event_reorder"
                else:
                    kind = "prev_hash_break"
            else:
                kind = "prev_hash_mismatch"
            event_failures.append(VerificationFailure(kind, _hex(details.canonical_event_hash)))

        # ADR 0069 D-3 / Core §19 step 4.h-temporal:
        # chain authored_at timestamps must be non-decreasing in chain order.
        if previous_authored_at is not None and details.authored_at < previous_authored_at:
            event_failures.append(
                VerificationFailure("timestamp_order_violation", _hex(details.canonical_event_hash))
            )

        previous_authored_at = details.authored_at
        previous_hash = details.canonical_event_hash

        # ADR 0005 step 8 input collection — every event contributes a
        # chain summary so the post-loop pass can flag `authored_at >
        # destroyed_at` events that sign under (post_erasure_use) or wrap
        # for (post_erasure_wrap) a destroyed kid.
        chain_summaries.append(
            _ChainEventSummary(
                event_index=index,
                authored_at=details.authored_at,
                signing_kid=event.kid,
                wrap_recipients=list(details.wrap_recipients),
                canonical_event_hash=details.canonical_event_hash,
            )
        )
        if details.erasure is not None:
            erasure_payloads.append(
                (index, details.erasure, details.canonical_event_hash)
            )
        if details.certificate is not None:
            certificate_payloads.append(
                (index, details.certificate, details.canonical_event_hash)
            )
        if details.user_content_attestation is not None:
            user_content_attestation_payloads.append(
                (index, details.user_content_attestation, details.canonical_event_hash)
            )
        decoded_events_for_uca.append(details)

        if details.transition is not None:
            tr = details.transition
            outcome = PostureTransitionOutcome(
                transition_id=tr.transition_id,
                kind=tr.kind,
                event_index=index,
                from_state=tr.from_state,
                to_state=tr.to_state,
                continuity_verified=True,
                declaration_resolved=True,
                attestations_verified=True,
                failures=[],
            )
            shadow_state = (
                shadow_custody_model
                if tr.kind == "custody-model"
                else shadow_disclosure_profile
            )
            if shadow_state is not None and tr.from_state != shadow_state:
                outcome.continuity_verified = False
                outcome.failures.append("state_continuity_mismatch")
            if posture_declaration is not None:
                exp_dd = domain_separated_sha256(POSTURE_DECLARATION_DOMAIN, posture_declaration)
                if exp_dd != tr.declaration_digest:
                    outcome.continuity_verified = False
                    outcome.declaration_resolved = False
                    outcome.failures.append("posture_declaration_digest_mismatch")
            if tr.kind == "custody-model":
                dual_required = _requires_dual_attestation(tr.from_state, tr.to_state)
            else:
                # Appendix A.5.3 step 4: Narrowing MAY be attested alone;
                # Widening and Orthogonal MUST be dually attested. Unknown
                # values fall through to dual as the conservative default.
                dual_required = tr.scope_change != "Narrowing"
            if dual_required and not (
                any(x == "prior" for x in tr.attestation_classes)
                and any(x == "new" for x in tr.attestation_classes)
            ):
                outcome.attestations_verified = False
                outcome.failures.append("attestation_insufficient")
            if outcome.failures:
                event_failures.append(
                    VerificationFailure(
                        outcome.failures[0], _hex(details.canonical_event_hash)
                    )
                )
            if tr.kind == "custody-model":
                shadow_custody_model = tr.to_state
            else:
                shadow_disclosure_profile = tr.to_state
            posture_transitions.append(outcome)

    erasure_evidence = _finalize_erasure_evidence(
        erasure_payloads,
        chain_summaries,
        registry,
        non_signing_registry,
        event_failures,
    )
    # ADR 0007 certificate-of-completion finalization (steps 2 / 5 / 6 / 7
    # / 8 cross-event reasoning). Step 4 (attachment lineage + content
    # recompute) defers to the export-bundle path; the genesis-append
    # path accumulates outcomes with `attachment_resolved = true` so the
    # §19 step-9 fold doesn't false-positive on minimal-genesis fixtures.
    certificates_of_completion = _finalize_certificates_of_completion(
        certificate_payloads,
        events,
        event_failures,
        payload_blobs,
        resolver=resolver,
    )
    # ADR 0010 §"Verifier obligations" finalization — runs steps 3-9
    # cross-event after every event has been decoded.
    user_content_attestations = _finalize_user_content_attestations(
        user_content_attestation_payloads,
        decoded_events_for_uca,
        registry,
        posture_declaration,
        identity_event_type_admitted,
        event_failures,
    )
    posture_ok = all(
        o.continuity_verified and o.declaration_resolved and o.attestations_verified
        for o in posture_transitions
    )
    # ADR 0005 step 10 fold: any erasure-evidence outcome with
    # `signature_verified = false`, `post_erasure_uses > 0`, or
    # `post_erasure_wraps > 0` flips integrity. Structure failures
    # (steps 1-6) already accumulated into `event_failures` so they
    # also gate via `not event_failures`.
    erasure_ok = all(
        o.signature_verified and o.post_erasure_uses == 0 and o.post_erasure_wraps == 0
        for o in erasure_evidence
    )
    # ADR 0007 §"Verifier obligations" + Core §19 step 9 fold: a
    # certificate outcome with chain_summary_consistent=False,
    # attachment_resolved=False, or all_signing_events_resolved=False
    # flips integrity.
    certificate_ok = all(
        o.chain_summary_consistent and o.attachment_resolved and o.all_signing_events_resolved
        for o in certificates_of_completion
    )
    # ADR 0010 §"Verifier obligations" step 9 fold — user-content
    # attestation outcomes flip integrity when chain-position binding,
    # identity resolution, signature verification, or key-state check
    # failed. Step-7 collision and step-8 operator-in-user-slot failures
    # already land in `event_failures` above.
    user_content_attestation_ok = all(
        o.chain_position_resolved
        and o.identity_resolved
        and o.signature_verified
        and o.key_active
        for o in user_content_attestations
    )
    return VerificationReport(
        structure_verified=True,
        integrity_verified=not event_failures
        and posture_ok
        and erasure_ok
        and certificate_ok
        and user_content_attestation_ok,
        readability_verified=True,
        event_failures=event_failures,
        checkpoint_failures=[],
        proof_failures=[],
        posture_transitions=posture_transitions,
        erasure_evidence=erasure_evidence,
        certificates_of_completion=certificates_of_completion,
        user_content_attestations=user_content_attestations,
        warnings=[],
    )


def _merkle_leaf_hash(canonical_hash: bytes) -> bytes:
    return domain_separated_sha256(MERKLE_LEAF_DOMAIN, canonical_hash)


def _merkle_interior_hash(left: bytes, right: bytes) -> bytes:
    joined = left + right
    return domain_separated_sha256(MERKLE_INTERIOR_DOMAIN, joined)


def _merkle_root(leaves: list[bytes]) -> bytes:
    if len(leaves) == 0:
        return bytes(32)
    if len(leaves) == 1:
        return leaves[0]
    level = list(leaves)
    while len(level) > 1:
        nxt: list[bytes] = []
        i = 0
        while i < len(level):
            if i + 1 == len(level):
                nxt.append(level[i])
            else:
                nxt.append(_merkle_interior_hash(level[i], level[i + 1]))
            i += 2
        level = nxt
    return level[0]


def _digest_path_from_values(nodes: list[Any]) -> list[bytes]:
    out: list[bytes] = []
    for node in nodes:
        if not isinstance(node, bytes) or len(node) != 32:
            raise ValueError("bad node")
        out.append(node)
    return out


def _inner_proof_size(index: int, size: int) -> int:
    xor = index ^ (size - 1)
    if xor == 0:
        return 0
    return xor.bit_length()


def _decomp_inclusion_proof(index: int, size: int) -> tuple[int, int]:
    inner = _inner_proof_size(index, size)
    border = (index >> inner).bit_count()
    return inner, border


def _chain_inner_merkle(seed: bytes, proof: list[bytes], index: int) -> bytes:
    for i, sibling in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = _merkle_interior_hash(seed, sibling)
        else:
            seed = _merkle_interior_hash(sibling, seed)
    return seed


def _chain_inner_right_merkle(seed: bytes, proof: list[bytes], index: int) -> bytes:
    for i, sibling in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = _merkle_interior_hash(sibling, seed)
    return seed


def _chain_border_right_merkle(seed: bytes, proof: list[bytes]) -> bytes:
    for sibling in proof:
        seed = _merkle_interior_hash(sibling, seed)
    return seed


def _root_from_inclusion_proof(
    leaf_index: int, tree_size: int, leaf_hash: bytes, proof: list[bytes]
) -> Optional[bytes]:
    if tree_size == 0 or leaf_index >= tree_size:
        return None
    inner, border = _decomp_inclusion_proof(leaf_index, tree_size)
    if len(proof) != inner + border:
        return None
    node = _chain_inner_merkle(leaf_hash, proof[:inner], leaf_index)
    node = _chain_border_right_merkle(node, proof[inner:])
    return node


def _root_from_consistency_proof(
    size1: int, size2: int, root1: bytes, proof: list[bytes]
) -> Optional[bytes]:
    if size2 < size1:
        return None
    if size1 == size2:
        if proof:
            return None
        return root1
    if size1 == 0:
        return None
    if not proof:
        return None
    inner, border = _decomp_inclusion_proof(size1 - 1, size2)
    shift = (size1 & -size1).bit_length() - 1  # trailing_zeros
    if inner < shift:
        return None
    inner -= shift
    seed = proof[0]
    start = 1
    if size1 == 1 << shift:
        seed = root1
        start = 0
    if len(proof) != start + inner + border:
        return None
    suffix = proof[start:]
    mask = (size1 - 1) >> shift
    hash1 = _chain_inner_right_merkle(seed, suffix[:inner], mask)
    hash1 = _chain_border_right_merkle(hash1, suffix[inner:])
    if hash1 != root1:
        return None
    hash2 = _chain_inner_merkle(seed, suffix[:inner], mask)
    return _chain_border_right_merkle(hash2, suffix[inner:])


def _checkpoint_digest(scope: bytes, payload_bytes: bytes) -> bytes:
    preimage = bytearray()
    preimage.append(0xA3)
    preimage.extend(encode_tstr("scope"))
    preimage.extend(encode_bstr(scope))
    preimage.extend(encode_tstr("version"))
    preimage.extend(encode_uint(1))
    preimage.extend(encode_tstr("checkpoint_payload"))
    preimage.extend(payload_bytes)
    return domain_separated_sha256(CHECKPOINT_DOMAIN, bytes(preimage))


def _map_lookup_array(m: dict, key: str) -> list[Any]:
    v = _map_lookup_str(m, key)
    if not isinstance(v, list):
        raise VerifyError(f"missing or invalid `{key}` array")
    return v


def _map_lookup_map(m: dict, key: str) -> dict:
    v = _map_lookup_str(m, key)
    if not isinstance(v, dict):
        raise VerifyError(f"missing or invalid `{key}` map")
    return v


def _map_lookup_optional_map(m: dict, key: str) -> Optional[dict]:
    v = m.get(key)
    if v is None:
        return None
    if isinstance(v, dict):
        return v
    raise VerifyError(f"`{key}` is not a map")


def _map_lookup_optional_extensions(manifest_map: dict) -> Optional[dict]:
    ext = manifest_map.get("extensions")
    if ext is None:
        return None
    if isinstance(ext, dict):
        return ext
    raise VerifyError("manifest extensions is not a map")


def _parse_attachment_export_extension(
    manifest_map: dict,
) -> Optional[tuple[bytes, bool]]:
    exts = _map_lookup_optional_extensions(manifest_map)
    if exts is None:
        return None
    ext = exts.get(ATTACHMENT_EXPORT_EXTENSION)
    if ext is None:
        return None
    if not isinstance(ext, dict):
        raise VerifyError("attachment export extension is not a map")
    digest = _map_lookup_fixed_bytes(ext, "attachment_manifest_digest", 32)
    inline = _map_lookup_bool(ext, "inline_attachments")
    return digest, inline


def _parse_erasure_evidence_export_extension(
    manifest_map: dict,
) -> Optional[tuple[str, bytes, int]]:
    exts = _map_lookup_optional_extensions(manifest_map)
    if exts is None:
        return None
    ext = exts.get(ERASURE_EVIDENCE_EXPORT_EXTENSION)
    if ext is None:
        return None
    if not isinstance(ext, dict):
        raise VerifyError("erasure export extension is not a map")
    catalog_ref = str(_map_lookup_str(ext, "catalog_ref"))
    if not catalog_ref.isascii():
        raise VerifyError("erasure export extension catalog_ref must be ASCII")
    digest = _map_lookup_fixed_bytes(ext, "catalog_digest", 32)
    entry_count = int(_map_lookup_u64(ext, "entry_count"))
    return catalog_ref, digest, entry_count


def _parse_erasure_catalog_entries(cat_bytes: bytes) -> list[dict[str, Any]]:
    root = _decode_value(cat_bytes)
    if not isinstance(root, list):
        raise VerifyError("erasure evidence catalog root is not an array")
    rows: list[dict[str, Any]] = []
    for entry in root:
        if not isinstance(entry, dict):
            raise VerifyError("erasure evidence catalog entry is not a map")
        scopes = _map_lookup_array(entry, "cascade_scopes")
        if not scopes:
            raise VerifyError("erasure evidence catalog cascade_scopes MUST be non-empty")
        cascade_scopes = []
        for s in scopes:
            if not isinstance(s, str):
                raise VerifyError("erasure catalog cascade_scope entry is not text")
            cascade_scopes.append(s)
        rows.append(
            {
                "canonical_event_hash": _map_lookup_fixed_bytes(
                    entry, "canonical_event_hash", 32
                ),
                "evidence_id": str(_map_lookup_str(entry, "evidence_id")),
                "kid_destroyed": _map_lookup_fixed_bytes(entry, "kid_destroyed", 16),
                "destroyed_at": _map_lookup_timestamp(entry, "destroyed_at"),
                "completion_mode": str(_map_lookup_str(entry, "completion_mode")),
                "cascade_scopes": cascade_scopes,
                "subject_scope_kind": str(_map_lookup_str(entry, "subject_scope_kind")),
            }
        )
    return rows


def _erasure_catalog_row_matches(row: dict[str, Any], det: EventDetails) -> bool:
    er = det.erasure
    if er is None:
        return False
    if row["canonical_event_hash"] != det.canonical_event_hash:
        return False
    if row["evidence_id"] != er.evidence_id:
        return False
    if row["kid_destroyed"] != er.kid_destroyed:
        return False
    if row["destroyed_at"] != er.destroyed_at:
        return False
    if row["completion_mode"] != er.completion_mode:
        return False
    if row["cascade_scopes"] != er.cascade_scopes:
        return False
    if row["subject_scope_kind"] != er.subject_scope_kind:
        return False
    return True


def _parse_certificate_export_extension(
    manifest_map: dict,
) -> Optional[tuple[str, bytes, int]]:
    """Parses the optional `trellis.export.certificates-of-completion.v1`
    manifest extension (ADR 0007 §"Export manifest catalog"). Mirror of
    Rust `parse_certificate_export_extension`."""
    exts = _map_lookup_optional_extensions(manifest_map)
    if exts is None:
        return None
    ext = exts.get(CERTIFICATE_EXPORT_EXTENSION)
    if ext is None:
        return None
    if not isinstance(ext, dict):
        raise VerifyError("certificate export extension is not a map")
    catalog_ref = str(_map_lookup_str(ext, "catalog_ref"))
    if not catalog_ref.isascii():
        raise VerifyError("certificate export extension catalog_ref must be ASCII")
    digest = _map_lookup_fixed_bytes(ext, "catalog_digest", 32)
    entry_count = int(_map_lookup_u64(ext, "entry_count"))
    return catalog_ref, digest, entry_count


def _parse_supersession_graph_export_extension(
    manifest_map: dict,
) -> Optional[tuple[bytes, int]]:
    exts = _map_lookup_optional_extensions(manifest_map)
    if exts is None:
        return None
    ext = exts.get(SUPERSESSION_GRAPH_EXPORT_EXTENSION)
    if ext is None:
        return None
    if not isinstance(ext, dict):
        raise VerifyError("supersession graph export extension is not a map")
    graph_digest = _map_lookup_fixed_bytes(ext, "graph_digest", 32)
    predecessor_count = int(_map_lookup_u64(ext, "predecessor_count"))
    return graph_digest, predecessor_count


def _parse_open_clocks_export_extension(
    manifest_map: dict,
) -> Optional[tuple[bytes, int]]:
    exts = _map_lookup_optional_extensions(manifest_map)
    if exts is None:
        return None
    ext = exts.get(OPEN_CLOCKS_EXPORT_EXTENSION)
    if ext is None:
        return None
    if not isinstance(ext, dict):
        raise VerifyError("open clocks export extension is not a map")
    digest = _map_lookup_fixed_bytes(ext, "open_clocks_digest", 32)
    count = int(_map_lookup_u64(ext, "open_clock_count"))
    return digest, count


def _parse_lower_hex(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        raise VerifyError(f"{field} is not a string")
    decoded = _hex_decode(value)
    if _hex(decoded) != value:
        raise VerifyError(f"{field} must be lowercase hexadecimal")
    return decoded


def _render_supersession_graph(graph: dict[str, Any]) -> str:
    rows = []
    for row in graph["predecessors"]:
        bundle = row["bundle_path"]
        if bundle is None:
            bundle_text = "null"
        else:
            bundle_text = json.dumps(bundle, ensure_ascii=False, separators=(",", ":"))
        rows.append(
            '{"bundle_path":'
            + bundle_text
            + ',"chain_id":"'
            + _hex(row["chain_id"])
            + '","checkpoint_hash":"'
            + _hex(row["checkpoint_hash"])
            + '"}'
        )
    return (
        '{"head_chain_id":"'
        + _hex(graph["head_chain_id"])
        + '","predecessors":['
        + ",".join(rows)
        + "]}\n"
    )


def _render_json_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _render_json_timestamp(value: TrellisTimestamp) -> str:
    return f"[{value.seconds},{value.nanos}]"


def _parse_json_timestamp(value: Any, field: str) -> TrellisTimestamp:
    if not isinstance(value, list) or len(value) != 2:
        raise VerifyError(f"{field} must be a two-element timestamp array")
    seconds, nanos = value
    if (
        not isinstance(seconds, int)
        or seconds < 0
        or not isinstance(nanos, int)
        or not (0 <= nanos <= 999_999_999)
    ):
        raise VerifyError(f"{field} must be [uint, uint <= 999999999]")
    return TrellisTimestamp(seconds, nanos)


def _render_open_clocks_catalog(catalog: dict[str, Any]) -> str:
    rows = []
    for row in catalog["open_clocks"]:
        rows.append(
            '{"clock_id":'
            + _render_json_string(row["clock_id"])
            + ',"clock_kind":'
            + _render_json_string(row["clock_kind"])
            + ',"computed_deadline":'
            + _render_json_timestamp(row["computed_deadline"])
            + ',"origin_event_hash":"'
            + _hex(row["origin_event_hash"])
            + '"}'
        )
    return (
        '{"open_clocks":['
        + ",".join(rows)
        + '],"sealed_at":'
        + _render_json_timestamp(catalog["sealed_at"])
        + "}\n"
    )


def _parse_open_clocks_catalog(data: bytes) -> dict[str, Any]:
    if data.startswith(b"\xef\xbb\xbf"):
        raise VerifyError("BOM is forbidden")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerifyError("catalog is not UTF-8") from exc
    if not text.endswith("\n") or "\n" in text[:-1]:
        raise VerifyError("catalog must have one trailing newline")
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise VerifyError(f"invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise VerifyError("catalog root is not an object")
    if list(value.keys()) != ["open_clocks", "sealed_at"]:
        raise VerifyError("catalog root keys are not exactly open_clocks/sealed_at")
    raw_rows = value["open_clocks"]
    if not isinstance(raw_rows, list):
        raise VerifyError("open_clocks is not an array")
    rows = []
    for raw_row in raw_rows:
        if not isinstance(raw_row, dict):
            raise VerifyError("open clock row is not an object")
        if list(raw_row.keys()) != [
            "clock_id",
            "clock_kind",
            "computed_deadline",
            "origin_event_hash",
        ]:
            raise VerifyError(
                "open clock row keys are not exactly "
                "clock_id/clock_kind/computed_deadline/origin_event_hash"
            )
        if not isinstance(raw_row["clock_id"], str):
            raise VerifyError("clock_id is not a string")
        if not isinstance(raw_row["clock_kind"], str):
            raise VerifyError("clock_kind is not a string")
        origin_event_hash = _parse_lower_hex(
            raw_row["origin_event_hash"], "origin_event_hash"
        )
        if len(origin_event_hash) != 32:
            raise VerifyError("origin_event_hash must decode to 32 bytes")
        rows.append(
            {
                "clock_id": raw_row["clock_id"],
                "clock_kind": raw_row["clock_kind"],
                "computed_deadline": _parse_json_timestamp(
                    raw_row["computed_deadline"], "computed_deadline"
                ),
                "origin_event_hash": origin_event_hash,
            }
        )
    for left, right in zip(rows, rows[1:]):
        if (left["origin_event_hash"], left["clock_id"].encode("utf-8")) > (
            right["origin_event_hash"],
            right["clock_id"].encode("utf-8"),
        ):
            raise VerifyError(
                "open_clocks rows must be ordered by origin_event_hash then clock_id"
            )
    catalog = {
        "open_clocks": rows,
        "sealed_at": _parse_json_timestamp(value["sealed_at"], "sealed_at"),
    }
    if _render_open_clocks_catalog(catalog).encode("utf-8") != data:
        raise VerifyError("catalog is not Trellis canonical JSON")
    return catalog


def _parse_supersession_graph(graph_bytes: bytes) -> dict[str, Any]:
    if graph_bytes.startswith(b"\xef\xbb\xbf"):
        raise VerifyError("BOM is forbidden")
    try:
        text = graph_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerifyError("graph is not UTF-8") from exc
    if not text.endswith("\n") or "\n" in text[:-1]:
        raise VerifyError("graph must have one trailing newline")
    try:
        root = json.loads(text)
    except json.JSONDecodeError as exc:
        raise VerifyError(f"invalid JSON: {exc}") from exc
    if not isinstance(root, dict):
        raise VerifyError("graph root is not an object")
    if list(root.keys()) != ["head_chain_id", "predecessors"]:
        raise VerifyError("graph root keys are not exactly head_chain_id/predecessors")
    predecessors_raw = root.get("predecessors")
    if not isinstance(predecessors_raw, list):
        raise VerifyError("predecessors is not an array")
    graph = {
        "head_chain_id": _parse_lower_hex(root.get("head_chain_id"), "head_chain_id"),
        "predecessors": [],
    }
    for row_raw in predecessors_raw:
        if not isinstance(row_raw, dict):
            raise VerifyError("predecessor row is not an object")
        if list(row_raw.keys()) != ["bundle_path", "chain_id", "checkpoint_hash"]:
            raise VerifyError(
                "predecessor row keys are not exactly bundle_path/chain_id/checkpoint_hash"
            )
        bundle_path = row_raw.get("bundle_path")
        if bundle_path is not None:
            if not isinstance(bundle_path, str):
                raise VerifyError("bundle_path must be null or a string")
            if not bundle_path.isascii() or not bundle_path.startswith(
                SUPERSESSION_PREDECESSOR_PREFIX
            ):
                raise VerifyError("bundle_path must be an ASCII 070-predecessors/ path")
        graph["predecessors"].append(
            {
                "bundle_path": bundle_path,
                "chain_id": _parse_lower_hex(row_raw.get("chain_id"), "chain_id"),
                "checkpoint_hash": _parse_lower_hex(
                    row_raw.get("checkpoint_hash"), "checkpoint_hash"
                ),
            }
        )
    for row in graph["predecessors"]:
        if len(row["checkpoint_hash"]) != 32:
            raise VerifyError("checkpoint_hash must decode to 32 bytes")
    if _render_supersession_graph(graph).encode("utf-8") != graph_bytes:
        raise VerifyError("graph is not Trellis canonical JSON")
    return graph


def _export_manifest_info(export_zip: bytes) -> tuple[bytes, bytes, Optional[tuple[bytes, int]]]:
    archive = parse_export_zip(export_zip)
    manifest = _parse_sign1_bytes(archive["000-manifest.cbor"])
    if manifest.payload is None:
        raise VerifyError("manifest payload is detached")
    payload = _decode_value(manifest.payload)
    if not isinstance(payload, dict):
        raise VerifyError("manifest payload root is not a map")
    return (
        _map_lookup_bytes(payload, "scope"),
        _map_lookup_fixed_bytes(payload, "head_checkpoint_digest", 32),
        _parse_supersession_graph_export_extension(payload),
    )


def _nested_supersession_graph(
    export_zip: bytes,
    nested_scope: bytes,
    extension: tuple[bytes, int],
    report: VerificationReport,
) -> Optional[tuple[dict[str, bytes], dict[str, Any]]]:
    archive = parse_export_zip(export_zip)
    graph_digest, predecessor_count = extension
    graph_bytes = archive.get(SUPERSESSION_GRAPH_MEMBER)
    if graph_bytes is None:
        report.event_failures.append(
            VerificationFailure("supersession_graph_invalid", SUPERSESSION_GRAPH_MEMBER)
        )
        return None
    if _sha256(graph_bytes) != graph_digest:
        report.event_failures.append(
            VerificationFailure("supersession_graph_invalid", SUPERSESSION_GRAPH_MEMBER)
        )
        return None
    try:
        graph = _parse_supersession_graph(graph_bytes)
    except VerifyError as exc:
        report.event_failures.append(
            VerificationFailure("supersession_graph_invalid", f"{SUPERSESSION_GRAPH_MEMBER}/{exc}")
        )
        return None
    if len(graph["predecessors"]) != predecessor_count:
        report.event_failures.append(
            VerificationFailure("supersession_graph_invalid", SUPERSESSION_GRAPH_MEMBER)
        )
    if graph["head_chain_id"] != nested_scope:
        report.event_failures.append(
            VerificationFailure("supersession_graph_head_mismatch", SUPERSESSION_GRAPH_MEMBER)
        )
    return archive, graph


def _verify_supersession_predecessor_bundles(
    archive: dict[str, bytes],
    graph: dict[str, Any],
    traversal_path: set[bytes],
    report: VerificationReport,
) -> None:
    for row in graph["predecessors"]:
        chain_id = row["chain_id"]
        if chain_id in traversal_path:
            report.event_failures.append(
                VerificationFailure("supersession_graph_cycle", SUPERSESSION_GRAPH_MEMBER)
            )
            continue
        traversal_path.add(chain_id)
        bundle_path = row["bundle_path"]
        if bundle_path is None:
            traversal_path.remove(chain_id)
            continue
        bundle_bytes = archive.get(bundle_path)
        if bundle_bytes is None:
            report.event_failures.append(
                VerificationFailure(
                    "supersession_predecessor_checkpoint_mismatch", bundle_path
                )
            )
            traversal_path.remove(chain_id)
            continue
        nested = verify_export_zip(bundle_bytes)
        if not nested.structure_verified or not nested.integrity_verified:
            report.event_failures.append(
                VerificationFailure(
                    "supersession_predecessor_checkpoint_mismatch", bundle_path
                )
            )
            traversal_path.remove(chain_id)
            continue
        try:
            nested_scope, digest, nested_ext = _export_manifest_info(bundle_bytes)
        except VerifyError:
            nested_scope, digest, nested_ext = b"", b"", None
        if digest != row["checkpoint_hash"] or nested_scope != chain_id:
            report.event_failures.append(
                VerificationFailure(
                    "supersession_predecessor_checkpoint_mismatch", bundle_path
                )
            )
            traversal_path.remove(chain_id)
            continue
        if nested_ext is not None:
            nested_graph = _nested_supersession_graph(
                bundle_bytes, nested_scope, nested_ext, report
            )
            if nested_graph is not None:
                nested_archive, nested_graph_value = nested_graph
                _verify_supersession_predecessor_bundles(
                    nested_archive, nested_graph_value, traversal_path, report
                )
        traversal_path.remove(chain_id)


def _verify_supersession_graph(
    archive: dict[str, bytes],
    events: list[ParsedSign1],
    scope: bytes,
    extension: tuple[bytes, int],
    report: VerificationReport,
) -> None:
    graph_digest, predecessor_count = extension
    graph_bytes = archive.get(SUPERSESSION_GRAPH_MEMBER)
    if graph_bytes is None:
        report.event_failures.append(
            VerificationFailure("supersession_graph_invalid", SUPERSESSION_GRAPH_MEMBER)
        )
        return
    if _sha256(graph_bytes) != graph_digest:
        report.event_failures.append(
            VerificationFailure("supersession_graph_invalid", SUPERSESSION_GRAPH_MEMBER)
        )
        return
    try:
        graph = _parse_supersession_graph(graph_bytes)
    except VerifyError as exc:
        report.event_failures.append(
            VerificationFailure("supersession_graph_invalid", f"{SUPERSESSION_GRAPH_MEMBER}/{exc}")
        )
        return
    if len(graph["predecessors"]) != predecessor_count:
        report.event_failures.append(
            VerificationFailure("supersession_graph_invalid", SUPERSESSION_GRAPH_MEMBER)
        )
    if graph["head_chain_id"] != scope:
        report.event_failures.append(
            VerificationFailure("supersession_graph_head_mismatch", SUPERSESSION_GRAPH_MEMBER)
        )

    for event in events:
        try:
            details = _decode_event_details(event)
        except VerifyError:
            continue
        linkage = details.supersedes_chain
        if linkage is None:
            continue
        if not any(
            row["chain_id"] == linkage.chain_id
            and row["checkpoint_hash"] == linkage.checkpoint_hash
            for row in graph["predecessors"]
        ):
            report.event_failures.append(
                VerificationFailure(
                    "supersession_graph_linkage_mismatch",
                    _hex(details.canonical_event_hash),
                )
            )

    seen: set[bytes] = set()
    for row in graph["predecessors"]:
        chain_id = row["chain_id"]
        if chain_id == graph["head_chain_id"] or chain_id in seen:
            report.event_failures.append(
                VerificationFailure("supersession_graph_cycle", SUPERSESSION_GRAPH_MEMBER)
            )
            break
        seen.add(chain_id)

    _verify_supersession_predecessor_bundles(
        archive, graph, {graph["head_chain_id"]}, report
    )


def _verify_open_clocks(
    archive: dict[str, bytes],
    extension: tuple[bytes, int],
    sealed_at: TrellisTimestamp,
    report: VerificationReport,
) -> None:
    expected_digest, expected_count = extension
    catalog_bytes = archive.get(OPEN_CLOCKS_MEMBER)
    if catalog_bytes is None:
        report.event_failures.append(
            VerificationFailure("archive_integrity_failure", OPEN_CLOCKS_MEMBER)
        )
        return
    if _sha256(catalog_bytes) != expected_digest:
        report.event_failures.append(
            VerificationFailure("archive_integrity_failure", OPEN_CLOCKS_MEMBER)
        )
        return
    try:
        catalog = _parse_open_clocks_catalog(catalog_bytes)
    except VerifyError as exc:
        report.event_failures.append(
            VerificationFailure(
                "manifest_payload_invalid", f"{OPEN_CLOCKS_MEMBER}/{exc}"
            )
        )
        return
    if len(catalog["open_clocks"]) != expected_count:
        report.event_failures.append(
            VerificationFailure("manifest_payload_invalid", OPEN_CLOCKS_MEMBER)
        )
    if catalog["sealed_at"] != sealed_at:
        report.event_failures.append(
            VerificationFailure("manifest_payload_invalid", f"{OPEN_CLOCKS_MEMBER}/sealed_at")
        )


def _parse_certificate_catalog_entries(cat_bytes: bytes) -> list[dict[str, Any]]:
    """Decodes `065-certificates-of-completion.cbor` entries (ADR 0007
    §"Export manifest catalog" `CertificateOfCompletionCatalogEntry`).
    Mirror of Rust `parse_certificate_catalog_entries`."""
    root = _decode_value(cat_bytes)
    if not isinstance(root, list):
        raise VerifyError("certificate catalog root is not an array")
    rows: list[dict[str, Any]] = []
    for entry in root:
        if not isinstance(entry, dict):
            raise VerifyError("certificate catalog entry is not a map")
        rows.append(
            {
                "canonical_event_hash": _map_lookup_fixed_bytes(
                    entry, "canonical_event_hash", 32
                ),
                "certificate_id":  str(_map_lookup_str(entry, "certificate_id")),
                "completed_at":    _map_lookup_timestamp(entry, "completed_at"),
                "signer_count":    int(_map_lookup_u64(entry, "signer_count")),
                "media_type":      str(_map_lookup_str(entry, "media_type")),
                "attachment_id":   str(_map_lookup_str(entry, "attachment_id")),
                "workflow_status": str(_map_lookup_str(entry, "workflow_status")),
            }
        )
    return rows


def _certificate_catalog_row_matches(row: dict[str, Any], det: EventDetails) -> bool:
    """Field-wise agreement check between a catalog row and the in-chain
    certificate event's decoded payload. Mirror of Rust
    `certificate_catalog_row_matches_details`."""
    cert = det.certificate
    if cert is None:
        return False
    if row["canonical_event_hash"] != det.canonical_event_hash:
        return False
    if row["certificate_id"] != cert.certificate_id:
        return False
    if row["completed_at"] != cert.completed_at:
        return False
    if row["signer_count"] != cert.chain_summary.signer_count:
        return False
    if row["media_type"] != cert.presentation_artifact.media_type:
        return False
    if row["attachment_id"] != cert.presentation_artifact.attachment_id:
        return False
    if row["workflow_status"] != cert.chain_summary.workflow_status:
        return False
    return True


def _verify_certificate_catalog(
    archive: dict[str, bytes],
    cert_ext: tuple[str, bytes, int],
    report: VerificationReport,
    event_by_hash: dict[bytes, EventDetails],
) -> None:
    """Verifies the optional `065-certificates-of-completion.cbor` catalog
    (ADR 0007 §"Export manifest catalog"). Mirror of Rust
    `verify_certificate_catalog`."""
    catalog_ref, catalog_digest, entry_count = cert_ext
    cat_bytes = archive.get(catalog_ref)
    if cat_bytes is None:
        report.event_failures.append(
            VerificationFailure("missing_certificate_catalog", catalog_ref)
        )
        return
    if _sha256(cat_bytes) != catalog_digest:
        report.event_failures.append(
            VerificationFailure("certificate_catalog_digest_mismatch", catalog_ref)
        )
    try:
        entries = _parse_certificate_catalog_entries(cat_bytes)
    except VerifyError as exc:
        report.event_failures.append(
            VerificationFailure(
                "certificate_catalog_invalid", f"{catalog_ref}/{exc}"
            )
        )
        return
    if len(entries) != entry_count:
        report.event_failures.append(
            VerificationFailure(
                "certificate_catalog_invalid", f"{catalog_ref}/entry_count"
            )
        )
    seen: set[bytes] = set()
    for row in entries:
        h = row["canonical_event_hash"]
        if h in seen:
            report.event_failures.append(
                VerificationFailure(
                    "certificate_catalog_duplicate_event", _hex(h)
                )
            )
        seen.add(h)
    for row in entries:
        h = row["canonical_event_hash"]
        det = event_by_hash.get(h)
        if det is None:
            report.event_failures.append(
                VerificationFailure(
                    "certificate_catalog_event_unresolved", _hex(h)
                )
            )
            continue
        if det.event_type != CERTIFICATE_EVENT_EXTENSION:
            report.event_failures.append(
                VerificationFailure(
                    "certificate_catalog_event_type_mismatch", _hex(h)
                )
            )
            continue
        if not _certificate_catalog_row_matches(row, det):
            report.event_failures.append(
                VerificationFailure("certificate_catalog_mismatch", _hex(h))
            )


def _verify_certificate_attachment_lineage(
    events: list[ParsedSign1],
    payload_blobs: dict[bytes, bytes],
    report: VerificationReport,
) -> None:
    """ADR 0007 §"Verifier obligations" step 4 — attachment lineage
    resolution + content-hash recompute. Mirror of Rust
    `verify_certificate_attachment_lineage`.

    For each in-scope certificate event:
    * resolve `presentation_artifact.attachment_id` via the chain's
      `trellis.evidence-attachment-binding.v1` events;
    * recover the bound attachment bytes from `payload_blobs`;
    * recompute SHA-256 over the bytes under domain tag
      `trellis-presentation-artifact-v1` (Core §9.8) and confirm equality
      with `presentation_artifact.content_hash`.

    Failure surfaces: `presentation_artifact_attachment_missing` (lineage
    unresolvable / bytes absent) — distinct from
    `presentation_artifact_content_mismatch` (lineage resolved, hash
    disagrees). Both flip `outcome.attachment_resolved`."""
    if not report.certificates_of_completion:
        return

    # Build attachment_id → AttachmentBindingDetails map.
    binding_by_attachment_id: dict[str, AttachmentBindingDetails] = {}
    for event in events:
        try:
            details = _decode_event_details(event)
        except VerifyError:
            continue
        if details.attachment_binding is not None:
            binding_by_attachment_id[details.attachment_binding.attachment_id] = (
                details.attachment_binding
            )

    # Build (global event index → EventDetails) map for certificate events.
    # Mirror of Rust's `cert_events_by_index` — must use the global index
    # because outcome.event_index is set against the unfiltered events vec.
    cert_events_by_index: dict[int, EventDetails] = {}
    for index, event in enumerate(events):
        try:
            details = _decode_event_details(event)
        except VerifyError:
            continue
        if details.certificate is not None:
            cert_events_by_index[index] = details

    for outcome in report.certificates_of_completion:
        details = cert_events_by_index.get(outcome.event_index)
        if details is None or details.certificate is None:
            outcome.attachment_resolved = False
            outcome.failures.append("presentation_artifact_attachment_missing")
            report.event_failures.append(
                VerificationFailure(
                    "presentation_artifact_attachment_missing",
                    outcome.certificate_id,
                )
            )
            continue
        canonical_hash_hex = _hex(details.canonical_event_hash)
        certificate = details.certificate
        binding = binding_by_attachment_id.get(
            certificate.presentation_artifact.attachment_id
        )
        if binding is None:
            outcome.attachment_resolved = False
            outcome.failures.append("presentation_artifact_attachment_missing")
            report.event_failures.append(
                VerificationFailure(
                    "presentation_artifact_attachment_missing", canonical_hash_hex
                )
            )
            continue
        attachment_bytes = payload_blobs.get(binding.payload_content_hash)
        if attachment_bytes is None:
            outcome.attachment_resolved = False
            outcome.failures.append("presentation_artifact_attachment_missing")
            report.event_failures.append(
                VerificationFailure(
                    "presentation_artifact_attachment_missing", canonical_hash_hex
                )
            )
            continue
        recomputed = domain_separated_sha256(
            PRESENTATION_ARTIFACT_DOMAIN, attachment_bytes
        )
        if recomputed != certificate.presentation_artifact.content_hash:
            outcome.attachment_resolved = False
            outcome.failures.append("presentation_artifact_content_mismatch")
            report.event_failures.append(
                VerificationFailure(
                    "presentation_artifact_content_mismatch", canonical_hash_hex
                )
            )


def _verify_erasure_evidence_catalog(
    archive: dict[str, bytes],
    erasure_ext: tuple[str, bytes, int],
    report: VerificationReport,
    event_by_hash: dict[bytes, EventDetails],
) -> None:
    catalog_ref, catalog_digest, entry_count = erasure_ext
    cat_bytes = archive.get(catalog_ref)
    if cat_bytes is None:
        report.event_failures.append(
            VerificationFailure("missing_erasure_evidence_catalog", catalog_ref)
        )
        return
    if _sha256(cat_bytes) != catalog_digest:
        report.event_failures.append(
            VerificationFailure(
                "erasure_evidence_catalog_digest_mismatch",
                catalog_ref,
            )
        )
    try:
        entries = _parse_erasure_catalog_entries(cat_bytes)
    except VerifyError as exc:
        report.event_failures.append(
            VerificationFailure(
                "erasure_evidence_catalog_invalid",
                f"{catalog_ref}/{exc}",
            )
        )
        return
    if len(entries) != entry_count:
        report.event_failures.append(
            VerificationFailure(
                "erasure_evidence_catalog_invalid",
                f"{catalog_ref}/entry_count",
            )
        )
    seen: set[bytes] = set()
    for row in entries:
        h = row["canonical_event_hash"]
        if h in seen:
            report.event_failures.append(
                VerificationFailure("erasure_evidence_catalog_duplicate_event", _hex(h))
            )
        seen.add(h)
    for row in entries:
        h = row["canonical_event_hash"]
        det = event_by_hash.get(h)
        if det is None:
            report.event_failures.append(
                VerificationFailure("erasure_evidence_catalog_event_unresolved", _hex(h))
            )
            continue
        if det.event_type != ERASURE_EVIDENCE_EVENT_EXTENSION:
            report.event_failures.append(
                VerificationFailure(
                    "erasure_evidence_catalog_event_type_mismatch",
                    _hex(h),
                )
            )
            continue
        if not _erasure_catalog_row_matches(row, det):
            report.event_failures.append(
                VerificationFailure("erasure_evidence_catalog_mismatch", _hex(h))
            )


def _map_lookup_optional_text(m: dict, key: str) -> Optional[str]:
    v = m.get(key)
    if v is None:
        return None
    if isinstance(v, str):
        return v
    raise VerifyError(f"`{key}` is neither text nor null")


def _map_lookup_str_alias(m: dict, key: str, legacy_key: str) -> str:
    try:
        return str(_map_lookup_str(m, key))
    except VerifyError:
        return str(_map_lookup_str(m, legacy_key))


def _parse_intake_handoff_details(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerifyError("handoff is not a map")
    initiation_mode = str(_map_lookup_str(value, "initiationMode"))
    case_ref = _map_lookup_optional_text(value, "caseRef")
    if initiation_mode == "workflowInitiated" and case_ref is None:
        raise VerifyError("workflowInitiated handoff is missing caseRef")
    if initiation_mode == "publicIntake" and case_ref is not None:
        raise VerifyError("publicIntake handoff caseRef must be null or absent")
    if initiation_mode not in ("workflowInitiated", "publicIntake"):
        raise VerifyError("handoff initiationMode is unsupported")
    definition_ref = _map_lookup_map(value, "definitionRef")
    response_hash = str(_map_lookup_str(value, "responseHash"))
    _parse_sha256_prefix_text(response_hash)
    return {
        "handoff_id": str(_map_lookup_str(value, "handoffId")),
        "initiation_mode": initiation_mode,
        "case_ref": case_ref,
        "definition_url": str(_map_lookup_str(definition_ref, "url")),
        "definition_version": str(_map_lookup_str(definition_ref, "version")),
        "response_ref": str(_map_lookup_str(value, "responseRef")),
        "response_hash": response_hash,
        "validation_report_ref": str(_map_lookup_str(value, "validationReportRef")),
        "ledger_head_ref": str(_map_lookup_str(value, "ledgerHeadRef")),
    }


def _first_array_text(outputs: list[Any]) -> Optional[str]:
    if not outputs:
        return None
    first = outputs[0]
    if isinstance(first, str):
        return first
    return None


def _parse_intake_accepted_record(payload_bytes: bytes) -> dict[str, Any]:
    v = _decode_value(payload_bytes)
    if not isinstance(v, dict):
        raise VerifyError("intake accepted payload root is not a map")
    record_kind = str(_map_lookup_str(v, "recordKind"))
    if record_kind != "intakeAccepted":
        raise VerifyError("intake accepted payload recordKind is not intakeAccepted")
    data = _map_lookup_map(v, "data")
    case_ref = str(_map_lookup_str(data, "caseRef"))
    outputs = _map_lookup_array(v, "outputs")
    output_case_ref = _first_array_text(outputs)
    if output_case_ref is None:
        raise VerifyError("intake accepted outputs array is missing or empty")
    if output_case_ref != case_ref:
        raise VerifyError("intake accepted outputs[0] does not match data.caseRef")
    return {
        "intake_id": str(_map_lookup_str(data, "intakeId")),
        "case_intent": str(_map_lookup_str(data, "caseIntent")),
        "case_disposition": str(_map_lookup_str(data, "caseDisposition")),
        "case_ref": case_ref,
        "definition_url": _map_lookup_optional_text(data, "definitionUrl"),
        "definition_version": _map_lookup_optional_text(data, "definitionVersion"),
    }


def _parse_intake_manifest_entries(data: bytes) -> list[dict[str, Any]]:
    v = _decode_value(data)
    if not isinstance(v, list):
        raise VerifyError("intake handoff catalog root is not an array")
    out: list[dict[str, Any]] = []
    for entry in v:
        if not isinstance(entry, dict):
            raise VerifyError("intake handoff catalog entry is not a map")
        handoff_raw = entry.get("handoff")
        if handoff_raw is None:
            raise VerifyError("missing `handoff`")
        handoff = _parse_intake_handoff_details(handoff_raw)
        out.append(
            {
                "intake_event_hash": _map_lookup_fixed_bytes(entry, "intake_event_hash", 32),
                "case_created_event_hash": _map_lookup_optional_fixed_bytes(
                    entry, "case_created_event_hash", 32
                ),
                "handoff": handoff,
                "response_bytes": _map_lookup_bytes(entry, "response_bytes"),
            }
        )
    return out


def _intake_entry_matches_record(entry: dict[str, Any], record: dict[str, Any]) -> bool:
    handoff = entry["handoff"]
    if handoff["handoff_id"] != record["intake_id"]:
        return False
    mode = handoff["initiation_mode"]
    if mode == "workflowInitiated":
        return (
            handoff.get("case_ref") == record["case_ref"]
            and record["case_intent"] == "attachToExistingCase"
            and record["case_disposition"] == "attachToExistingCase"
        )
    if mode == "publicIntake":
        return (
            record["case_intent"] == "requestGovernedCaseCreation"
            and record["case_disposition"] == "createGovernedCase"
            and record.get("definition_url") == handoff["definition_url"]
            and record.get("definition_version") == handoff["definition_version"]
        )
    return False


def _case_created_record_matches_handoff(
    entry: dict[str, Any], intake_record: dict[str, Any], case_record: dict[str, Any]
) -> bool:
    handoff = entry["handoff"]
    return (
        case_record["case_ref"] == intake_record["case_ref"]
        and case_record["intake_handoff_ref"] == handoff["handoff_id"]
        and case_record["formspec_response_ref"] == handoff["response_ref"]
        and case_record["validation_report_ref"] == handoff["validation_report_ref"]
        and case_record["ledger_head_ref"] == handoff["ledger_head_ref"]
        and case_record["initiation_mode"] == handoff["initiation_mode"]
    )


def _response_hash_matches(value: str, response_bytes: bytes) -> tuple[bool, Optional[str]]:
    try:
        expected = _parse_sha256_prefix_text(value)
    except VerifyError as exc:
        return False, str(exc)
    actual = _sha256(response_bytes)
    return (actual == expected), None


def _parse_attachment_manifest_entries(data: bytes) -> list[dict[str, Any]]:
    v = _decode_value(data)
    if not isinstance(v, list):
        raise VerifyError("attachment manifest root is not an array")
    out: list[dict[str, Any]] = []
    for entry in v:
        if not isinstance(entry, dict):
            raise VerifyError("attachment manifest entry is not a map")
        out.append(
            {
                "binding_event_hash": _map_lookup_fixed_bytes(entry, "binding_event_hash", 32),
                "attachment_id": str(_map_lookup_str(entry, "attachment_id")),
                "slot_path": str(_map_lookup_str(entry, "slot_path")),
                "media_type": str(_map_lookup_str(entry, "media_type")),
                "byte_length": _map_lookup_u64(entry, "byte_length"),
                "attachment_sha256": _map_lookup_fixed_bytes(entry, "attachment_sha256", 32),
                "payload_content_hash": _map_lookup_fixed_bytes(entry, "payload_content_hash", 32),
                "filename": entry.get("filename"),
                "prior_binding_hash": _map_lookup_optional_fixed_bytes(
                    entry, "prior_binding_hash", 32
                ),
            }
        )
    return out


def _binding_lineage_graph_has_cycle(adj: dict[bytes, list[bytes]]) -> bool:
    class Color:
        WHITE = 0
        GRAY = 1
        BLACK = 2

    nodes: set[bytes] = set()
    for frm, tos in adj.items():
        nodes.add(frm)
        nodes.update(tos)
    color: dict[bytes, int] = {n: Color.WHITE for n in nodes}

    def dfs(node: bytes) -> bool:
        c = color.get(node, Color.WHITE)
        if c == Color.GRAY:
            return True
        if c == Color.BLACK:
            return False
        color[node] = Color.GRAY
        for nxt in adj.get(node, []):
            if dfs(nxt):
                return True
        color[node] = Color.BLACK
        return False

    for n in list(nodes):
        if color.get(n, Color.WHITE) == Color.WHITE and dfs(n):
            return True
    return False


def _attachment_manifest_topology_failures(
    entries: list[dict[str, Any]], hash_to_index: dict[bytes, int]
) -> list[VerificationFailure]:
    failures: list[VerificationFailure] = []
    seen: set[bytes] = set()
    for e in entries:
        bh = e["binding_event_hash"]
        if bh in seen:
            failures.append(
                VerificationFailure("attachment_manifest_duplicate_binding", _hex(bh))
            )
        seen.add(bh)
    adj: dict[bytes, list[bytes]] = defaultdict(list)
    for e in entries:
        prior = e.get("prior_binding_hash")
        if prior is None:
            continue
        bh = e["binding_event_hash"]
        if bh in hash_to_index and prior in hash_to_index:
            adj[bh].append(prior)
    if _binding_lineage_graph_has_cycle(dict(adj)):
        failures.append(
            VerificationFailure("attachment_binding_lineage_cycle", "061-attachments.cbor")
        )
    for e in entries:
        prior = e.get("prior_binding_hash")
        if prior is None:
            continue
        bh = e["binding_event_hash"]
        cur_i = hash_to_index.get(bh)
        pri_i = hash_to_index.get(prior)
        if cur_i is None or pri_i is None:
            failures.append(
                VerificationFailure("attachment_prior_binding_unresolved", _hex(bh))
            )
            continue
        if pri_i >= cur_i:
            failures.append(
                VerificationFailure(
                    "attachment_prior_binding_forward_reference", _hex(bh)
                )
            )
    return failures


def _attachment_entry_matches_binding(
    entry: dict[str, Any], binding: AttachmentBindingDetails
) -> bool:
    if entry["attachment_id"] != binding.attachment_id:
        return False
    if entry["slot_path"] != binding.slot_path:
        return False
    if entry["media_type"] != binding.media_type:
        return False
    if entry["byte_length"] != binding.byte_length:
        return False
    if entry["attachment_sha256"] != binding.attachment_sha256:
        return False
    if entry["payload_content_hash"] != binding.payload_content_hash:
        return False
    fn = entry.get("filename")
    if fn != binding.filename:
        return False
    if entry.get("prior_binding_hash") != binding.prior_binding_hash:
        return False
    return True


def _verify_attachment_manifest(
    archive: dict[str, bytes],
    events: list[ParsedSign1],
    manifest_digest: bytes,
    inline_attachments: bool,
    report: VerificationReport,
) -> None:
    man_bytes = archive.get("061-attachments.cbor")
    if man_bytes is None:
        report.event_failures.append(
            VerificationFailure("missing_attachment_manifest", "061-attachments.cbor")
        )
        return
    if _sha256(man_bytes) != manifest_digest:
        report.event_failures.append(
            VerificationFailure("attachment_manifest_digest_mismatch", "061-attachments.cbor")
        )
    try:
        entries = _parse_attachment_manifest_entries(man_bytes)
    except VerifyError as exc:
        report.event_failures.append(
            VerificationFailure("attachment_manifest_invalid", f"061-attachments.cbor/{exc}")
        )
        return
    details_list: list[EventDetails] = []
    for ev in events:
        try:
            details_list.append(_decode_event_details(ev))
        except VerifyError:
            continue
    hash_to_index: dict[bytes, int] = {}
    for index, ev in enumerate(events):
        try:
            d = _decode_event_details(ev)
            hash_to_index[d.canonical_event_hash] = index
        except VerifyError:
            continue
    for f in _attachment_manifest_topology_failures(entries, hash_to_index):
        report.event_failures.append(f)
    for e in entries:
        bh = e["binding_event_hash"]
        matches = [d for d in details_list if d.canonical_event_hash == bh]
        if len(matches) != 1:
            report.event_failures.append(
                VerificationFailure("attachment_binding_event_unresolved", _hex(bh))
            )
            continue
        det = matches[0]
        binding = det.attachment_binding
        if binding is None:
            report.event_failures.append(
                VerificationFailure("attachment_binding_missing", _hex(bh))
            )
            continue
        if not _attachment_entry_matches_binding(e, binding):
            report.event_failures.append(
                VerificationFailure("attachment_binding_mismatch", _hex(bh))
            )
            continue
        if e["payload_content_hash"] != det.content_hash or binding.payload_content_hash != det.content_hash:
            report.event_failures.append(
                VerificationFailure("attachment_payload_hash_mismatch", _hex(bh))
            )
            continue
        if inline_attachments:
            member = f"060-payloads/{_hex(e['payload_content_hash'])}.bin"
            if member not in archive:
                report.event_failures.append(
                    VerificationFailure("missing_attachment_body", member)
                )


def _readable_payload_bytes(
    details: EventDetails, payload_blobs: dict[bytes, bytes]
) -> Optional[bytes]:
    if details.payload_ref_inline is not None:
        return details.payload_ref_inline
    if details.payload_ref_external:
        return payload_blobs.get(details.content_hash)
    return None


def _parse_signature_catalog_entries(data: bytes) -> list[dict[str, Any]]:
    v = _decode_value(data)
    if not isinstance(v, list):
        raise VerifyError("signature catalog root is not an array")
    rows: list[dict[str, Any]] = []
    for entry in v:
        if not isinstance(entry, dict):
            raise VerifyError("signature catalog entry is not a map")
        pr = entry.get("profile_ref")
        pk = entry.get("profile_key")
        ib = entry.get("identity_binding")
        cr = entry.get("consent_reference")
        if not isinstance(ib, dict) or not isinstance(cr, dict):
            raise VerifyError("identity_binding or consent_reference is not a map")
        rows.append(
            {
                "canonical_event_hash": _map_lookup_fixed_bytes(
                    entry, "canonical_event_hash", 32
                ),
                "signer_id": str(_map_lookup_str(entry, "signer_id")),
                "role_id": str(_map_lookup_str(entry, "role_id")),
                "role": str(_map_lookup_str(entry, "role")),
                "document_id": str(_map_lookup_str(entry, "document_id")),
                "document_hash": str(_map_lookup_str(entry, "document_hash")),
                "document_hash_algorithm": str(_map_lookup_str(entry, "document_hash_algorithm")),
                "signed_at": str(_map_lookup_str(entry, "signed_at")),
                "identity_binding": ib,
                "consent_reference": cr,
                "signature_provider": str(_map_lookup_str(entry, "signature_provider")),
                "ceremony_id": str(_map_lookup_str(entry, "ceremony_id")),
                "source_signature_system": str(
                    _map_lookup_str(entry, "source_signature_system")
                ),
                "source_signature_id": str(_map_lookup_str(entry, "source_signature_id")),
                "signed_payload_digest": str(_map_lookup_str(entry, "signed_payload_digest")),
                "signed_payload_digest_algorithm": str(
                    _map_lookup_str(entry, "signed_payload_digest_algorithm")
                ),
                "signing_intent": str(_map_lookup_str(entry, "signing_intent")),
                "profile_ref": str(pr) if isinstance(pr, str) else None,
                "profile_key": str(pk) if isinstance(pk, str) else None,
                "source_response_ref": _map_lookup_str_alias(
                    entry, "source_response_ref", "formspec_response_ref"
                ),
            }
        )
    return rows


def _signature_entry_matches_record(entry: dict[str, Any], record: dict[str, Any]) -> bool:
    if entry["signer_id"] != record["signer_id"]:
        return False
    if entry["role_id"] != record["role_id"]:
        return False
    if entry["role"] != record["role"]:
        return False
    if entry["document_id"] != record["document_id"]:
        return False
    if entry["document_hash"] != record["document_hash"]:
        return False
    if entry["document_hash_algorithm"] != record["document_hash_algorithm"]:
        return False
    if entry["signed_at"] != record["signed_at"]:
        return False
    if not _cbor_nested_semantic_eq(entry["identity_binding"], record["identity_binding"]):
        return False
    if not _cbor_nested_semantic_eq(entry["consent_reference"], record["consent_reference"]):
        return False
    if entry["signature_provider"] != record["signature_provider"]:
        return False
    if entry["ceremony_id"] != record["ceremony_id"]:
        return False
    if entry["source_signature_system"] != record["source_signature_system"]:
        return False
    if entry["source_signature_id"] != record["source_signature_id"]:
        return False
    if entry["signed_payload_digest"] != record["signed_payload_digest"]:
        return False
    if entry["signed_payload_digest_algorithm"] != record["signed_payload_digest_algorithm"]:
        return False
    if entry["signing_intent"] != record["signing_intent"]:
        return False
    if entry["profile_ref"] != record["profile_ref"]:
        return False
    if entry["profile_key"] != record["profile_key"]:
        return False
    if entry["source_response_ref"] != record["source_response_ref"]:
        return False
    return True


def _index_events_by_canonical_hash(
    events: list[ParsedSign1],
) -> tuple[dict[bytes, EventDetails], list[VerificationFailure]]:
    """Single pass for signature + intake catalog verifiers; duplicate failures once."""
    event_by_hash: dict[bytes, EventDetails] = {}
    duplicate_failures: list[VerificationFailure] = []
    for ev in events:
        try:
            d = _decode_event_details(ev)
        except VerifyError:
            continue
        if d.canonical_event_hash in event_by_hash:
            duplicate_failures.append(
                VerificationFailure(
                    "export_events_duplicate_canonical_hash",
                    _hex(d.canonical_event_hash),
                )
            )
            continue
        event_by_hash[d.canonical_event_hash] = d
    return event_by_hash, duplicate_failures


def parse_export_zip(data: bytes) -> dict[str, bytes]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data), "r")
    except Exception as exc:  # noqa: BLE001
        raise VerifyError(f"failed to parse ZIP: {exc}") from exc
    members: dict[str, bytes] = {}
    try:
        for info in zf.infolist():
            name = info.filename
            if "/" not in name:
                raise VerifyError("ZIP member does not live under one export root")
            _, relative = name.split("/", 1)
            with zf.open(info) as fh:
                members[relative] = fh.read()
    finally:
        zf.close()
    return members


def _verify_interop_sidecars(
    manifest_map: dict, archive: dict[str, bytes]
) -> tuple[list[InteropSidecarVerificationEntry], Optional[VerificationReport]]:
    """ADR 0008 §"Phase-1 verifier obligation" — Wave 25 dispatched
    verifier (path-(b): digest-binds only). Walks
    `manifest.interop_sidecars` and the on-disk `interop-sidecars/`
    tree and produces one outcome per dispatched-kind entry.

    Failure order per entry (first failure wins; mirrors
    ``trellis_verify::verify_interop_sidecars``): kind-registered →
    derivation-version-supported (``c2pa-manifest`` only) → path-prefix
    valid → phase-1 lock-off → listed-file present (``interop_sidecar_missing``)
    → content-digest match (``interop_sidecar_content_mismatch``); then
    unlisted files under ``interop-sidecars/`` after the manifest walk.

    Returns ``(outcomes, fatal_report_or_None)``. When the second
    element is non-None, the caller MUST short-circuit and return it
    as the verifier's report (mirrors Rust ``Result<Vec<...>,
    VerificationReport>`` short-circuit). Mirrors
    ``trellis_verify::verify_interop_sidecars``.
    """
    raw = manifest_map.get("interop_sidecars")
    if raw is None:
        return [], None
    if not isinstance(raw, list):
        return [], VerificationReport.fatal(
            "manifest_payload_invalid",
            "interop_sidecars must be an array or null",
        )

    outcomes: list[InteropSidecarVerificationEntry] = []
    listed_paths: set[str] = set()

    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            return [], VerificationReport.fatal(
                "manifest_payload_invalid",
                f"interop_sidecars[{index}] is not a map",
            )
        try:
            kind = entry["kind"]
            if not isinstance(kind, str):
                raise VerifyError(f"interop_sidecars[{index}].kind is not a string")
            path = entry["path"]
            if not isinstance(path, str):
                raise VerifyError(f"interop_sidecars[{index}].path is not a string")
            derivation_version = entry["derivation_version"]
            if not isinstance(derivation_version, int) or not (
                0 <= derivation_version <= 255
            ):
                raise VerifyError(
                    f"interop_sidecars[{index}].derivation_version out of range"
                )
            content_digest = entry["content_digest"]
            if not isinstance(content_digest, bytes) or len(content_digest) != 32:
                raise VerifyError(
                    f"interop_sidecars[{index}].content_digest must be 32 bytes"
                )
            source_ref = entry.get("source_ref")
            if not isinstance(source_ref, str):
                raise VerifyError(
                    f"interop_sidecars[{index}].source_ref must be a string"
                )
        except (KeyError, VerifyError) as exc:
            return [], VerificationReport.fatal(
                "manifest_payload_invalid",
                f"interop_sidecars[{index}] is invalid: {exc}",
            )

        # Step 2.a (kind-registered) — TR-CORE-164.
        if kind not in _INTEROP_SIDECAR_REGISTERED_KINDS:
            return [], VerificationReport.fatal(
                "interop_sidecar_kind_unknown",
                f"interop_sidecars[{index}].kind {kind!r} is not in the ADR 0008 registry",
            )

        # Step 2.b (derivation-version-supported) — TR-CORE-166.
        if (
            kind == "c2pa-manifest"
            and derivation_version
            not in _INTEROP_SIDECAR_C2PA_MANIFEST_SUPPORTED_VERSIONS
        ):
            return [], VerificationReport.fatal(
                "interop_sidecar_derivation_version_unknown",
                f"interop_sidecars[{index}] kind={kind!r} "
                f"derivation_version={derivation_version} not in supported set",
            )

        # Step 2.c (path-prefix-valid) — TR-CORE-167.
        if not _is_interop_sidecar_path_valid(path):
            return [], VerificationReport.fatal(
                "interop_sidecar_path_invalid",
                f"interop_sidecars[{index}].path {path!r} does not start with "
                f"{_INTEROP_SIDECARS_PATH_PREFIX!r}",
            )

        # Step 2.d (Phase-1 lock-off — three locked kinds short-circuit
        # AFTER passing structural checks). Wave 25 unlocks
        # `c2pa-manifest@v1` only.
        if kind != "c2pa-manifest":
            return [], VerificationReport.fatal(
                "interop_sidecar_phase_1_locked",
                f"interop_sidecars[{index}] kind={kind!r} is still Phase-1 locked-off "
                "(ADR 0008 / ADR 0003)",
            )

        # Step 2.e (listed-file-present) — TR-CORE-168. Absence is a catalog
        # omission, not a digest mismatch (TR-CORE-163 is step 2.f only).
        actual_bytes = archive.get(path)
        if actual_bytes is None:
            return [], VerificationReport.fatal(
                "interop_sidecar_missing",
                f"interop_sidecars[{index}].path {path!r} is missing from the export ZIP",
            )
        actual_digest = domain_separated_sha256(CONTENT_DOMAIN, actual_bytes)
        if actual_digest != content_digest:
            return [], VerificationReport.fatal(
                "interop_sidecar_content_mismatch",
                f"interop_sidecars[{index}].content_digest does not match "
                f"SHA-256(trellis-content-v1, {path!r})",
            )

        listed_paths.add(path)
        outcomes.append(
            InteropSidecarVerificationEntry(
                kind=kind,
                path=path,
                derivation_version=derivation_version,
                content_digest_ok=True,
                kind_registered=True,
                phase_1_locked=False,
                failures=[],
            )
        )

    # Step 2.f (unlisted-file) — TR-CORE-165.
    for member_path in archive:
        if not member_path.startswith(_INTEROP_SIDECARS_PATH_PREFIX):
            continue
        if member_path in listed_paths:
            continue
        return [], VerificationReport.fatal(
            "interop_sidecar_unlisted_file",
            f"{member_path!r} is present under interop-sidecars/ but not catalogued in "
            "manifest.interop_sidecars",
        )

    return outcomes, None


def verify_export_zip(
    export_zip: bytes,
    identity_event_type_admitted: Callable[[str], bool] = _is_identity_attestation_event_type,
    resolver: Optional[ResponseProofResolver] = None,
) -> VerificationReport:
    try:
        archive = parse_export_zip(export_zip)
    except VerifyError as exc:
        return VerificationReport.fatal("export_zip_invalid", f"failed to open export ZIP: {exc}")

    reg_bytes = archive.get("030-signing-key-registry.cbor")
    if reg_bytes is None:
        return VerificationReport.fatal(
            "missing_signing_key_registry", "export is missing 030-signing-key-registry.cbor"
        )
    try:
        registry, non_signing_registry = _parse_key_registry(reg_bytes)
    except VerifyError as exc:
        # Core §8.7.3 step 3 / TR-CORE-048: structural shape failures surface
        # under the typed kind tag (e.g. ``key_entry_attributes_shape_mismatch``)
        # rather than the generic ``signing_key_registry_invalid``.
        kind = exc.kind or "signing_key_registry_invalid"
        return VerificationReport.fatal(
            kind, f"failed to decode signing-key registry: {exc}"
        )

    manifest_bytes = archive.get("000-manifest.cbor")
    if manifest_bytes is None:
        return VerificationReport.fatal("missing_manifest", "export is missing 000-manifest.cbor")
    try:
        manifest = _parse_sign1_bytes(manifest_bytes)
    except VerifyError as exc:
        return VerificationReport.fatal(
            "manifest_structure_invalid", f"manifest is not a valid COSE_Sign1 envelope: {exc}"
        )

    if manifest.alg != ALG_EDDSA or manifest.suite_id != SUITE_ID_PHASE_1:
        return VerificationReport.fatal(
            "unsupported_suite", "manifest protected header does not match the Trellis Phase-1 suite"
        )

    manifest_entry = registry.get(manifest.kid)
    if manifest_entry is None:
        return VerificationReport.fatal(
            "unresolvable_manifest_kid",
            "manifest kid is not resolvable via the embedded signing-key registry",
        )
    if not _verify_signature(manifest, manifest_entry.public_key):
        return VerificationReport.fatal("manifest_signature_invalid", "manifest COSE signature is invalid")

    if manifest.payload is None:
        return VerificationReport.fatal(
            "manifest_payload_missing", "manifest payload is detached, which is out of scope for Phase 1"
        )
    try:
        manifest_payload = _decode_value(manifest.payload)
    except VerifyError as exc:
        return VerificationReport.fatal(
            "manifest_payload_invalid", f"failed to decode manifest payload: {exc}"
        )
    if not isinstance(manifest_payload, dict):
        return VerificationReport.fatal("manifest_payload_invalid", "manifest payload root is not a map")
    manifest_map = manifest_payload

    # ADR 0008 §"Phase-1 verifier obligation" — Wave 25 dispatched
    # verifier (path-(b): digest-binds only). Mirrors Rust
    # `trellis_verify::verify_interop_sidecars`. The `c2pa-manifest@v1`
    # kind dispatches to per-entry verification; the three other
    # registered kinds (`scitt-receipt`, `vc-jose-cose-event`,
    # `did-key-view`) remain Phase-1 locked-off. Outcomes accumulate
    # into `interop_sidecars` for the dispatched-kind entries; lock-off
    # / unknown-kind / version-unknown / path-invalid / content-mismatch
    # / unlisted-file all short-circuit via `VerificationReport.fatal`
    # (Core §19.1 / TR-CORE-145, 163..167).
    interop_sidecars_outcomes, fatal_report = _verify_interop_sidecars(
        manifest_map, archive
    )
    if fatal_report is not None:
        return fatal_report

    required_digests = [
        ("010-events.cbor", "events_digest"),
        ("020-inclusion-proofs.cbor", "inclusion_proofs_digest"),
        ("025-consistency-proofs.cbor", "consistency_proofs_digest"),
        ("030-signing-key-registry.cbor", "signing_key_registry_digest"),
        ("040-checkpoints.cbor", "checkpoints_digest"),
    ]
    for member_name, field_name in required_digests:
        try:
            expected = _map_lookup_fixed_bytes(manifest_map, field_name, 32)
        except VerifyError as exc:
            return VerificationReport.fatal(
                "manifest_payload_invalid", f"manifest is missing {field_name}: {exc}"
            )
        actual_bytes = archive.get(member_name)
        if actual_bytes is None:
            return VerificationReport.fatal(
                "archive_integrity_failure", f"export is missing required member {member_name}"
            )
        if expected != _sha256(actual_bytes):
            return VerificationReport.fatal(
                "archive_integrity_failure", f"manifest digest mismatch for {member_name}"
            )

    try:
        registry_bindings = _map_lookup_array(manifest_map, "registry_bindings")
    except VerifyError as exc:
        return VerificationReport.fatal(
            "manifest_payload_invalid", f"manifest registry_bindings are invalid: {exc}"
        )
    parsed_bindings: list[RegistryBindingInfo] = []
    for binding in registry_bindings:
        if not isinstance(binding, dict):
            return VerificationReport.fatal(
                "manifest_payload_invalid", "registry binding is not a map"
            )
        try:
            digest = _map_lookup_fixed_bytes(binding, "registry_digest", 32)
            member_name = f"050-registries/{_hex(digest)}.cbor"
            actual = archive.get(member_name)
            if actual is None:
                return VerificationReport.fatal(
                    "archive_integrity_failure",
                    f"export is missing bound registry member {member_name}",
                )
            if _sha256(actual) != digest:
                return VerificationReport.fatal(
                    "archive_integrity_failure",
                    f"bound registry digest mismatch for {member_name}",
                )
            bound_at_sequence = _map_lookup_u64(binding, "bound_at_sequence")
        except VerifyError as exc:
            return VerificationReport.fatal(
                "manifest_payload_invalid", f"registry binding digest is invalid: {exc}"
            )
        parsed_bindings.append(RegistryBindingInfo(digest_hex=_hex(digest), bound_at_sequence=bound_at_sequence))
    parsed_bindings.sort(key=lambda b: b.bound_at_sequence)

    parsed_registries: dict[str, BoundRegistry] = {}
    for binding in parsed_bindings:
        member_name = f"050-registries/{binding.digest_hex}.cbor"
        registry_member_bytes = archive[member_name]
        try:
            parsed_registries[binding.digest_hex] = _parse_bound_registry(registry_member_bytes)
        except VerifyError as exc:
            return VerificationReport.fatal(
                "bound_registry_invalid", f"failed to decode {member_name}: {exc}"
            )

    try:
        scope = _map_lookup_bytes(manifest_map, "scope")
    except VerifyError as exc:
        return VerificationReport.fatal("manifest_payload_invalid", f"manifest scope is invalid: {exc}")
    try:
        generated_at = _map_lookup_timestamp(manifest_map, "generated_at")
    except VerifyError as exc:
        return VerificationReport.fatal(
            "manifest_payload_invalid", f"manifest generated_at is invalid: {exc}"
        )

    events_bytes = archive["010-events.cbor"]
    try:
        events = _parse_sign1_array(events_bytes)
    except VerifyError as exc:
        return VerificationReport.fatal("events_invalid", f"failed to decode 010-events.cbor: {exc}")

    payload_blobs: dict[bytes, bytes] = {}
    for name, blob in archive.items():
        if not name.startswith("060-payloads/") or not name.endswith(".bin"):
            continue
        digest_hex = name[len("060-payloads/") : -len(".bin")]
        try:
            d = _hex_decode(digest_hex)
        except VerifyError:
            continue
        if len(d) == 32:
            payload_blobs[d] = blob

    report = _verify_event_set(
        events,
        registry,
        None,
        None,
        False,
        scope,
        payload_blobs,
        non_signing_registry=non_signing_registry,
        identity_event_type_admitted=identity_event_type_admitted,
        resolver=resolver,
    )
    # ADR 0008 / Core §18.3a — Wave 25 dispatched-verifier outcomes.
    # `_verify_interop_sidecars` already short-circuited any fatal
    # path through `fatal_report` above; what reaches this site is the
    # per-entry success slice. The export integrity-fold below treats
    # absent failures as pass-through.
    report.interop_sidecars = interop_sidecars_outcomes
    try:
        attachment_export = _parse_attachment_export_extension(manifest_map)
    except VerifyError as exc:
        return VerificationReport.fatal(
            "manifest_payload_invalid", f"attachment export extension is invalid: {exc}"
        )
    if attachment_export is not None:
        att_digest, att_inline = attachment_export
        _verify_attachment_manifest(archive, events, att_digest, att_inline, report)
    try:
        erasure_export_ext = _parse_erasure_evidence_export_extension(manifest_map)
    except VerifyError as exc:
        return VerificationReport.fatal(
            "manifest_payload_invalid", f"erasure export extension is invalid: {exc}"
        )
    try:
        certificate_export_ext = _parse_certificate_export_extension(manifest_map)
    except VerifyError as exc:
        return VerificationReport.fatal(
            "manifest_payload_invalid",
            f"certificate export extension is invalid: {exc}",
        )
    try:
        supersession_graph_ext = _parse_supersession_graph_export_extension(manifest_map)
    except VerifyError as exc:
        return VerificationReport.fatal(
            "manifest_payload_invalid",
            f"supersession graph export extension is invalid: {exc}",
        )
    try:
        open_clocks_ext = _parse_open_clocks_export_extension(manifest_map)
    except VerifyError as exc:
        return VerificationReport.fatal(
            "manifest_payload_invalid",
            f"open clocks export extension is invalid: {exc}",
        )
    shared_event_by_hash: dict[bytes, EventDetails] = {}
    if erasure_export_ext is not None or certificate_export_ext is not None:
        shared_event_by_hash, dup_failures = _index_events_by_canonical_hash(events)
        report.event_failures.extend(dup_failures)
    if erasure_export_ext is not None:
        _verify_erasure_evidence_catalog(
            archive, erasure_export_ext, report, shared_event_by_hash
        )
    # ADR 0007 §"Verifier obligations" step 4 — export-bundle context
    # resolves attachment lineage + recomputes content hash. Runs
    # unconditionally so certificate events that travel without the
    # optional manifest catalog still get step-4 enforcement (mirrors Rust
    # `verify_certificate_attachment_lineage` dispatch in
    # `verify_export_zip`).
    _verify_certificate_attachment_lineage(events, payload_blobs, report)
    if certificate_export_ext is not None:
        _verify_certificate_catalog(
            archive, certificate_export_ext, report, shared_event_by_hash
        )
    if supersession_graph_ext is None and SUPERSESSION_GRAPH_MEMBER in archive:
        report.event_failures.append(
            VerificationFailure("supersession_graph_unbound", SUPERSESSION_GRAPH_MEMBER)
        )
    if supersession_graph_ext is not None:
        _verify_supersession_graph(
            archive, events, scope, supersession_graph_ext, report
        )
    if open_clocks_ext is None and OPEN_CLOCKS_MEMBER in archive:
        report.event_failures.append(
            VerificationFailure("manifest_payload_invalid", OPEN_CLOCKS_MEMBER)
        )
    if open_clocks_ext is not None:
        _verify_open_clocks(archive, open_clocks_ext, generated_at, report)

    for failure in report.event_failures:
        if failure.kind == "scope_mismatch":
            failure.location = f"manifest-scope/{failure.location}"

    for event in events:
        try:
            details = _decode_event_details(event)
        except VerifyError:
            continue
        eligible = [b for b in parsed_bindings if b.bound_at_sequence <= details.sequence]
        if not eligible:
            report.event_failures.append(
                VerificationFailure("registry_digest_mismatch", _hex(details.canonical_event_hash))
            )
            continue
        binding = max(eligible, key=lambda b: b.bound_at_sequence)
        bound_registry = parsed_registries.get(binding.digest_hex)
        if bound_registry is None:
            report.event_failures.append(
                VerificationFailure("registry_digest_mismatch", _hex(details.canonical_event_hash))
            )
            continue
        if (details.event_type not in bound_registry.event_types) or (
            details.classification not in bound_registry.classifications
        ):
            report.event_failures.append(
                VerificationFailure("registry_digest_mismatch", _hex(details.canonical_event_hash))
            )

    canonical_hashes = []
    for event in events:
        try:
            _, ch = _event_identity(event)
            canonical_hashes.append(ch)
        except Exception:  # noqa: BLE001
            continue
    leaf_hashes = [_merkle_leaf_hash(h) for h in canonical_hashes]

    checkpoints_bytes = archive["040-checkpoints.cbor"]
    try:
        checkpoints = _parse_sign1_array(checkpoints_bytes)
    except VerifyError as exc:
        return VerificationReport.fatal("checkpoints_invalid", f"failed to decode 040-checkpoints.cbor: {exc}")

    prior_checkpoint_digest: Optional[bytes] = None
    head_checkpoint_root: Optional[bytes] = None
    for checkpoint in checkpoints:
        ck_entry = registry.get(checkpoint.kid)
        if ck_entry is None:
            return VerificationReport.fatal(
                "unresolvable_manifest_kid",
                "checkpoint kid is not resolvable via the embedded signing-key registry",
            )
        if not _verify_signature(checkpoint, ck_entry.public_key):
            return VerificationReport.fatal(
                "checkpoint_signature_invalid", "checkpoint COSE signature is invalid"
            )
        payload_bytes_chk = checkpoint.payload
        if payload_bytes_chk is None:
            return VerificationReport.fatal("checkpoint_payload_invalid", "detached checkpoint")
        try:
            payload = _decode_value(payload_bytes_chk)
        except VerifyError as exc:
            return VerificationReport.fatal(
                "checkpoint_payload_invalid", f"failed to decode checkpoint payload: {exc}"
            )
        if not isinstance(payload, dict):
            return VerificationReport.fatal(
                "checkpoint_payload_invalid", "checkpoint payload root is not a map"
            )
        try:
            checkpoint_scope = _map_lookup_bytes(payload, "scope")
        except VerifyError as exc:
            return VerificationReport.fatal(
                "checkpoint_payload_invalid", f"checkpoint scope is invalid: {exc}"
            )
        if checkpoint_scope != scope:
            report.checkpoint_failures.append(
                VerificationFailure("scope_mismatch", "checkpoint/scope")
            )
            continue
        try:
            tree_size = _map_lookup_u64(payload, "tree_size")
        except VerifyError as exc:
            return VerificationReport.fatal(
                "checkpoint_payload_invalid", f"checkpoint tree_size is invalid: {exc}"
            )
        if tree_size == 0 or tree_size > len(leaf_hashes):
            report.checkpoint_failures.append(
                VerificationFailure("tree_size_invalid", f"checkpoint/tree_size/{tree_size}")
            )
            continue
        try:
            actual_root = _map_lookup_fixed_bytes(payload, "tree_head_hash", 32)
        except VerifyError as exc:
            return VerificationReport.fatal(
                "checkpoint_payload_invalid", f"checkpoint tree_head_hash is invalid: {exc}"
            )
        expected_root = _merkle_root(leaf_hashes[:tree_size])
        if expected_root != actual_root:
            report.checkpoint_failures.append(
                VerificationFailure("checkpoint_root_mismatch", f"checkpoint/tree_size/{tree_size}")
            )

        digest = _checkpoint_digest(scope, payload_bytes_chk)
        if prior_checkpoint_digest is not None:
            try:
                actual_prev = _map_lookup_fixed_bytes(payload, "prev_checkpoint_hash", 32)
            except VerifyError as exc:
                return VerificationReport.fatal(
                    "checkpoint_payload_invalid",
                    f"checkpoint prev_checkpoint_hash is invalid: {exc}",
                )
            if prior_checkpoint_digest != actual_prev:
                report.checkpoint_failures.append(
                    VerificationFailure(
                        "prev_checkpoint_hash_mismatch", f"checkpoint/tree_size/{tree_size}"
                    )
                )
        prior_checkpoint_digest = digest
        head_checkpoint_root = actual_root

    try:
        head_checkpoint_digest = _map_lookup_fixed_bytes(manifest_map, "head_checkpoint_digest", 32)
    except VerifyError as exc:
        return VerificationReport.fatal(
            "manifest_payload_invalid", f"manifest head_checkpoint_digest is invalid: {exc}"
        )
    if prior_checkpoint_digest != head_checkpoint_digest:
        report.checkpoint_failures.append(
            VerificationFailure("head_checkpoint_digest_mismatch", "manifest/head_checkpoint_digest")
        )

    inclusion_map = _decode_value(archive["020-inclusion-proofs.cbor"])
    if isinstance(inclusion_map, dict):
        expected_root = head_checkpoint_root if head_checkpoint_root is not None else bytes(32)
        for _k, proof_value in inclusion_map.items():
            if not isinstance(proof_value, dict):
                report.proof_failures.append(VerificationFailure("inclusion_proof_invalid", "proof/map"))
                continue
            pm = proof_value
            try:
                tree_size_p = _map_lookup_u64(pm, "tree_size")
                leaf_index = _map_lookup_u64(pm, "leaf_index")
                leaf_hash = _map_lookup_fixed_bytes(pm, "leaf_hash", 32)
                audit_path_values = _map_lookup_array(pm, "audit_path")
                audit_path = _digest_path_from_values(audit_path_values)
            except (VerifyError, ValueError):
                report.proof_failures.append(VerificationFailure("inclusion_proof_invalid", "proof/map"))
                continue
            if tree_size_p != len(leaf_hashes):
                report.proof_failures.append(
                    VerificationFailure("inclusion_proof_invalid", f"proof/tree_size/{tree_size_p}")
                )
                continue
            if leaf_index >= len(leaf_hashes):
                report.proof_failures.append(
                    VerificationFailure("inclusion_proof_invalid", f"proof/index/{leaf_index}")
                )
                continue
            matches_leaf = leaf_hash == leaf_hashes[leaf_index]
            rr = _root_from_inclusion_proof(leaf_index, tree_size_p, leaf_hash, audit_path)
            matches_root = rr is not None and rr == expected_root
            if not matches_leaf or not matches_root:
                report.proof_failures.append(
                    VerificationFailure("inclusion_proof_mismatch", f"proof/index/{leaf_index}")
                )

    consistency_value = _decode_value(archive["025-consistency-proofs.cbor"])
    if isinstance(consistency_value, list):
        for record in consistency_value:
            if not isinstance(record, dict):
                report.proof_failures.append(
                    VerificationFailure("consistency_proof_invalid", "consistency/map")
                )
                continue
            rm = record
            from_tree_size = int(rm.get("from_tree_size", 0) or 0)
            to_tree_size = int(rm.get("to_tree_size", 0) or 0)
            location = f"consistency/{from_tree_size}-{to_tree_size}"
            try:
                proof_path_values = _map_lookup_array(rm, "proof_path")
                proof_path = _digest_path_from_values(proof_path_values)
            except (VerifyError, ValueError):
                report.proof_failures.append(
                    VerificationFailure(
                        "consistency_proof_invalid", f"{location}/proof_path"
                    )
                )
                continue
            if from_tree_size == 0:
                report.proof_failures.append(
                    VerificationFailure("consistency_proof_invalid", f"{location}/from_zero")
                )
                continue
            if from_tree_size >= to_tree_size or to_tree_size > len(leaf_hashes):
                report.proof_failures.append(
                    VerificationFailure("consistency_proof_invalid", location)
                )
                continue
            root_old = _merkle_root(leaf_hashes[:from_tree_size])
            root_new = _merkle_root(leaf_hashes[:to_tree_size])
            cr = _root_from_consistency_proof(from_tree_size, to_tree_size, root_old, proof_path)
            if cr != root_new:
                report.proof_failures.append(
                    VerificationFailure("consistency_proof_mismatch", location)
                )

    report.structure_verified = True
    report.integrity_verified = (
        not report.event_failures
        and not report.checkpoint_failures
        and not report.proof_failures
        and all(
            o.continuity_verified and o.declaration_resolved and o.attestations_verified
            for o in report.posture_transitions
        )
        and all(
            o.signature_verified and o.post_erasure_uses == 0 and o.post_erasure_wraps == 0
            for o in report.erasure_evidence
        )
        and all(
            o.chain_summary_consistent
            and o.attachment_resolved
            and o.all_signing_events_resolved
            for o in report.certificates_of_completion
        )
        # ADR 0010 §19 step 9 fold — matches Rust `verify_export_zip` tail
        # (`lib.rs`) so export integrity stays aligned with genesis-path logic.
        and all(
            o.chain_position_resolved
            and o.identity_resolved
            and o.signature_verified
            and o.key_active
            for o in report.user_content_attestations
        )
        # ADR 0008 §"Phase-1 verifier obligation" / Core §18.3a — Wave 25
        # dispatched-verifier integrity fold. Today every non-pass
        # condition short-circuits via `fatal`; this fold is defensive
        # against a future sub-fatal failure surface. Mirrors Rust
        # `trellis-verify`.
        and all(
            o.content_digest_ok
            and o.kind_registered
            and not o.phase_1_locked
            and not o.failures
            for o in report.interop_sidecars
        )
    )
    report.readability_verified = True
    return report


def verify_tampered_ledger(
    signing_key_registry: bytes,
    ledger: bytes,
    initial_posture_declaration: Optional[bytes] = None,
    posture_declaration: Optional[bytes] = None,
    identity_event_type_admitted: Callable[[str], bool] = _is_identity_attestation_event_type,
    resolver: Optional[ResponseProofResolver] = None,
) -> VerificationReport:
    try:
        registry, non_signing_registry = _parse_key_registry(signing_key_registry)
    except VerifyError as exc:
        # See verify_export_zip for rationale on the typed kind tag.
        kind = exc.kind or "signing_key_registry_invalid"
        return VerificationReport.fatal(
            kind, f"failed to decode signing-key registry: {exc}"
        )
    try:
        events = _parse_sign1_array(ledger)
    except Exception:  # noqa: BLE001
        events = []
    if not events:
        return VerificationReport.fatal(
            "malformed_cose", "ledger is not a non-empty dCBOR array of COSE_Sign1 events"
        )
    return _verify_event_set(
        events,
        registry,
        initial_posture_declaration,
        posture_declaration,
        True,
        None,
        None,
        non_signing_registry=non_signing_registry,
        identity_event_type_admitted=identity_event_type_admitted,
        resolver=resolver,
    )


def verify_single_event(
    public_key_bytes: bytes,
    signed_event: bytes,
    identity_event_type_admitted: Callable[[str], bool] = _is_identity_attestation_event_type,
    resolver: Optional[ResponseProofResolver] = None,
) -> VerificationReport:
    try:
        parsed = _parse_sign1_bytes(signed_event)
    except VerifyError as exc:
        return VerificationReport.fatal("malformed_cose", str(exc))
    registry = {parsed.kid: SigningKeyEntry(public_key=public_key_bytes, status=0, valid_to=None)}
    return _verify_event_set(
        [parsed],
        registry,
        None,
        None,
        False,
        None,
        None,
        identity_event_type_admitted=identity_event_type_admitted,
        resolver=resolver,
    )
