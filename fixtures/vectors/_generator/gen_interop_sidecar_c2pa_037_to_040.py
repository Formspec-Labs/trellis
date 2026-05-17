"""Generate Wave 25 interop-sidecar fixtures for the c2pa-manifest@v1
dispatched verifier:

* `export/014-interop-sidecar-c2pa-manifest`        — positive
* `tamper/037-interop-sidecar-content-mismatch`     — TR-CORE-163
* `tamper/038-interop-sidecar-kind-unknown`         — TR-CORE-164
* `tamper/039-interop-sidecar-unlisted-file`        — TR-CORE-165
* `tamper/040-interop-sidecar-derivation-version-unknown` — TR-CORE-166
* `tamper/044-interop-sidecar-missing`              — TR-CORE-168

Authoring aid only. The committed fixture bytes are the evidence
surface; this script exists so the CBOR + ZIP output is reproducible.

Strategy: take `export/012-interop-sidecars-empty-list/expected-export.zip`
as the base (a known-valid Phase-1 export with `interop_sidecars: []`),
re-emit the manifest with a populated `interop_sidecars` field and an
accompanying `interop-sidecars/c2pa-manifest/<file>` member, and re-sign
the manifest under `_keys/issuer-001.cose_key`. Per Core §18.3a / ADR
0008 §"Phase-1 verifier obligation" Wave 25:

* Positive sidecar payload is a deterministic synthetic dCBOR map
  carrying the five-field Trellis assertion shape (the actual C2PA
  manifest store would wrap this; for path-(b) digest-only verification,
  the bytes need not be a real C2PA manifest — the verifier only
  recomputes SHA-256 under `trellis-content-v1` and compares to
  `manifest.interop_sidecars[i].content_digest`).
* Per-tamper mutation: each fixture varies exactly one surface vs the
  positive (content bytes / kind / unlisted file / derivation_version).

ISC-02 deterministic derivation: re-running this generator MUST yield
byte-identical output.
"""
from __future__ import annotations

import copy
import hashlib
import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cbor2  # noqa: E402
from cbor2 import CBORTag  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from _lib.byte_utils import (  # noqa: E402
    ALG_EDDSA,
    CBOR_TAG_COSE_SIGN1,
    COSE_LABEL_ALG,
    COSE_LABEL_KID,
    COSE_LABEL_SUITE_ID,
    ARTIFACT_TYPE_CHECKPOINT,
    ARTIFACT_TYPE_EVENT,
    ARTIFACT_TYPE_MANIFEST,
    COSE_LABEL_ARTIFACT_TYPE,
    SUITE_ID_PHASE_1,
    dcbor,
    deterministic_zipinfo,
    domain_separated_sha256,
)


ROOT = Path(__file__).resolve().parent.parent
KEY_ISSUER = ROOT / "_keys" / "issuer-001.cose_key"

BASE_EXPORT_ZIP = ROOT / "export" / "012-interop-sidecars-empty-list" / "expected-export.zip"

OUT_EXPORT_014 = ROOT / "export" / "014-interop-sidecar-c2pa-manifest"
OUT_TAMPER_037 = ROOT / "tamper" / "037-interop-sidecar-content-mismatch"
OUT_TAMPER_038 = ROOT / "tamper" / "038-interop-sidecar-kind-unknown"
OUT_TAMPER_039 = ROOT / "tamper" / "039-interop-sidecar-unlisted-file"
OUT_TAMPER_040 = ROOT / "tamper" / "040-interop-sidecar-derivation-version-unknown"
OUT_TAMPER_044 = ROOT / "tamper" / "044-interop-sidecar-missing"

CONTENT_DOMAIN = "trellis-content-v1"
SIDECAR_PATH = "interop-sidecars/c2pa-manifest/cert-wave25-001.c2pa"
SIDECAR_PATH_UNREGISTERED = "interop-sidecars/made-up-kind/some.bin"
SIDECAR_UNLISTED_PATH = "interop-sidecars/c2pa-manifest/stray.cbor"

# Synthetic Trellis-assertion bytes — five-field dCBOR map. Mirrors
# `trellis-interop-c2pa::emit_c2pa_manifest_for_certificate` shape so the
# fixture and the adapter exercise the same byte format. Real C2PA
# manifests would wrap this assertion inside their manifest store; for
# path-(b) digest verification, the wrapping is irrelevant.
ASSERTION_FIELDS = {
    "trellis.canonical_event_hash":            bytes([0x11] * 32),
    "trellis.certificate_id":                  "cert-wave25-001",
    "trellis.cose_sign1_ref":                  bytes([0x44] * 32),
    "trellis.kid":                             bytes([0x33] * 16),
    "trellis.presentation_artifact.content_hash": bytes([0x22] * 32),
}


def synthetic_assertion_bytes() -> bytes:
    # cbor2 with canonical=True emits map keys in canonical order.
    return dcbor(ASSERTION_FIELDS)


SIDECAR_BYTES = synthetic_assertion_bytes()
SIDECAR_BYTES_TAMPERED = synthetic_assertion_bytes()[:-1] + bytes(
    [(synthetic_assertion_bytes()[-1] ^ 0xFF) & 0xFF]
)


# ---------------------------------------------------------------------------
# Helpers — mirror gen_export_010 conventions.
# ---------------------------------------------------------------------------


def load_seed_and_pubkey(path: Path) -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(path.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert len(seed) == 32 and len(pubkey) == 32
    return seed, pubkey


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def protected_header(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> bytes:
    return dcbor(
        {
            COSE_LABEL_ALG: ALG_EDDSA,
            COSE_LABEL_KID: kid,
            COSE_LABEL_SUITE_ID: SUITE_ID_PHASE_1, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
        }
    )


def cose_sign1(seed: bytes, kid: bytes, payload_bytes: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> bytes:
    protected = protected_header(kid, artifact_type)
    sig_structure = dcbor(["Signature1", protected, b"", payload_bytes])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    return dcbor(CBORTag(CBOR_TAG_COSE_SIGN1, [protected, {}, payload_bytes, signature]))


def parse_zip_members(zip_bytes: bytes) -> tuple[str, dict[str, bytes]]:
    """Return (export_root_dir, {relative_path: bytes})."""
    members: dict[str, bytes] = {}
    root = None
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for info in zf.infolist():
            name = info.filename
            head, _, tail = name.partition("/")
            if root is None:
                root = head
            elif root != head:
                raise RuntimeError(f"unexpected second export root: {head}")
            members[tail] = zf.read(info)
    assert root is not None, "empty ZIP"
    return root, members


def write_deterministic_zip(root: str, members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        # Sort by path for determinism (Core §18.1).
        for relative in sorted(members):
            arcname = f"{root}/{relative}"
            info = deterministic_zipinfo(arcname)
            zf.writestr(info, members[relative])
        # Patch external_attr = 0 on every entry; CPython overwrites
        # zero attrs back to `0o600 << 16` on writestr (see gen_export_001).
        for entry in zf.filelist:
            entry.external_attr = 0
    return buf.getvalue()


def decode_manifest_payload(manifest_bytes: bytes) -> tuple[dict, bytes, bytes]:
    """Decode the COSE_Sign1-wrapped manifest. Returns
    (decoded_payload_map, kid, protected_bytes_unused)."""
    tagged = cbor2.loads(manifest_bytes)
    assert isinstance(tagged, CBORTag) and tagged.tag == CBOR_TAG_COSE_SIGN1
    protected_bytes, _unprotected, payload_bytes, _sig = tagged.value
    protected = cbor2.loads(protected_bytes)
    kid = protected[COSE_LABEL_KID]
    payload = cbor2.loads(payload_bytes)
    return payload, kid, protected_bytes


def emit_signed_manifest(
    seed: bytes, kid: bytes, payload: dict
) -> bytes:
    payload_bytes = dcbor(payload)
    return cose_sign1(seed, kid, payload_bytes, ARTIFACT_TYPE_MANIFEST)


# ---------------------------------------------------------------------------
# Core builder: produces a mutated export ZIP with the requested
# `interop_sidecars` field and on-disk sidecar tree.
# ---------------------------------------------------------------------------


def build_export_zip(
    base_zip_bytes: bytes,
    seed: bytes,
    sidecar_entries: list[dict],
    sidecar_files: dict[str, bytes],
) -> bytes:
    """Re-emit the base export ZIP with `manifest.interop_sidecars =
    sidecar_entries` and the given sidecar-tree files. Re-signs the
    manifest under `seed` (the issuer key from the embedded registry).

    `sidecar_entries` is the list to splice into the manifest payload
    (each entry already shaped per Core §28 InteropSidecarEntry CDDL).
    `sidecar_files` is a relative-path → bytes map for files to
    inject under the export root (typically `interop-sidecars/<kind>/<file>`).
    """
    root, members = parse_zip_members(base_zip_bytes)
    manifest_bytes = members["000-manifest.cbor"]
    payload, kid, _protected = decode_manifest_payload(manifest_bytes)

    new_payload = copy.deepcopy(payload)
    new_payload["interop_sidecars"] = sidecar_entries

    members["000-manifest.cbor"] = emit_signed_manifest(seed, kid, new_payload)
    for path, blob in sidecar_files.items():
        members[path] = blob
    return write_deterministic_zip(root, members)


def write_fixture(
    out_dir: Path,
    manifest_toml: str,
    inputs: dict[str, bytes],
) -> str:
    """Write fixture members. Returns the SHA-256 hex of the canonical
    ZIP if one was provided as `inputs["expected-export.zip"]`, else
    the empty string."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for filename, blob in inputs.items():
        (out_dir / filename).write_bytes(blob)
    (out_dir / "manifest.toml").write_text(manifest_toml, encoding="utf-8")
    if "expected-export.zip" in inputs:
        return hashlib.sha256(inputs["expected-export.zip"]).hexdigest()
    return ""


# ---------------------------------------------------------------------------
# Per-fixture builders.
# ---------------------------------------------------------------------------


def build_positive_entry(
    content_digest: bytes, path: str = SIDECAR_PATH, derivation_version: int = 1
) -> dict:
    return {
        "kind": "c2pa-manifest",
        "derivation_version": derivation_version,
        "path": path,
        "content_digest": content_digest,
        "source_ref": "trellis:event:cert-wave25-001",
    }


def gen_export_014(seed: bytes, base_zip: bytes) -> tuple[bytes, dict[str, bytes], str]:
    """Positive: c2pa-manifest@v1 entry, file present, digest matches.

    Uses the `export` op so the directory-name lint (check-specs.py
    rule: `<op>/<slug>` must agree with `manifest.op`) accepts the
    `export/014-...` slot per the Wave 25 brief. The conformance
    walker rebuilds the ZIP byte-for-byte from `input-ledger-state.cbor`
    + per-member files; we ship every member from the mutated bundle
    individually so the walker's byte-exact replay closes.

    Returns `(zip_bytes, members_by_relative_path, manifest_toml)`.
    """
    content_digest = domain_separated_sha256(CONTENT_DOMAIN, SIDECAR_BYTES)
    entry = build_positive_entry(content_digest)
    zip_bytes = build_export_zip(
        base_zip, seed,
        sidecar_entries=[entry],
        sidecar_files={SIDECAR_PATH: SIDECAR_BYTES},
    )

    # Decode the freshly-built ZIP back into per-member bytes plus the
    # root_dir; the walker re-zips from these.
    root, members = parse_zip_members(zip_bytes)

    # Build the input-ledger-state.cbor mirroring export/012 schema.
    ledger_state = {
        "version": 1,
        "scope": b"test-response-ledger-2",  # mirrors base export
        "tree_size": 2,
        "root_dir": root,
        "members": sorted(members.keys()),
        "notes": (
            "Wave 25 export/014. Mutated from "
            "export/012-interop-sidecars-empty-list with "
            "interop_sidecars: [<one c2pa-manifest@v1 entry>] and an "
            "interop-sidecars/c2pa-manifest/cert-wave25-001.c2pa file."
        ),
    }
    members_with_state = dict(members)

    manifest_toml = f"""\
id          = "export/014-interop-sidecar-c2pa-manifest"
op          = "export"
status      = "active"
description = \"\"\"Wave 25 positive — manifest lists one
`c2pa-manifest@v1` entry; the sidecar file at
`interop-sidecars/c2pa-manifest/cert-wave25-001.c2pa` is present and
its SHA-256 (under `trellis-content-v1`) matches manifest
`content_digest`. Phase-1 verifier (path-(b): digest-binds only) returns
`structure_verified = integrity_verified = readability_verified = true`;
`VerificationReport.interop_sidecars` carries one outcome with
`content_digest_ok = kind_registered = true`, `phase_1_locked = false`.
Anchors TR-CORE-145 (envelope reservation posture under Wave 25
narrowing).\"\"\"

[coverage]
tr_core = ["TR-CORE-145"]

[inputs]
ledger_state = "input-ledger-state.cbor"

[expected]
zip        = "expected-export.zip"
zip_sha256 = "{hashlib.sha256(zip_bytes).hexdigest()}"

[derivation]
document = "derivation.md"
"""

    members_with_state["__ledger_state__"] = dcbor(ledger_state)
    return zip_bytes, members_with_state, manifest_toml


def gen_tamper_037(seed: bytes, base_zip: bytes) -> bytes:
    """tamper/037 — content mismatch. Manifest claims the positive
    digest; on-disk sidecar bytes are flipped one byte. Verifier emits
    `interop_sidecar_content_mismatch`."""
    content_digest = domain_separated_sha256(CONTENT_DOMAIN, SIDECAR_BYTES)
    entry = build_positive_entry(content_digest)
    zip_bytes = build_export_zip(
        base_zip, seed,
        sidecar_entries=[entry],
        sidecar_files={SIDECAR_PATH: SIDECAR_BYTES_TAMPERED},
    )
    return zip_bytes


def gen_tamper_038(seed: bytes, base_zip: bytes) -> bytes:
    """tamper/038 — kind unknown. Manifest lists `kind = "made-up-kind"`;
    verifier emits `interop_sidecar_kind_unknown` before any digest check."""
    content_digest = domain_separated_sha256(CONTENT_DOMAIN, SIDECAR_BYTES)
    entry = {
        "kind": "made-up-kind",
        "derivation_version": 1,
        "path": SIDECAR_PATH_UNREGISTERED,
        "content_digest": content_digest,
        "source_ref": "trellis:event:cert-wave25-001",
    }
    zip_bytes = build_export_zip(
        base_zip, seed,
        sidecar_entries=[entry],
        sidecar_files={SIDECAR_PATH_UNREGISTERED: SIDECAR_BYTES},
    )
    return zip_bytes


def gen_tamper_039(seed: bytes, base_zip: bytes) -> bytes:
    """tamper/039 — unlisted file. Manifest lists ONE entry; on-disk
    tree contains TWO files under `interop-sidecars/`. Verifier emits
    `interop_sidecar_unlisted_file` after the manifest walk completes."""
    content_digest = domain_separated_sha256(CONTENT_DOMAIN, SIDECAR_BYTES)
    entry = build_positive_entry(content_digest)
    zip_bytes = build_export_zip(
        base_zip, seed,
        sidecar_entries=[entry],
        sidecar_files={
            SIDECAR_PATH: SIDECAR_BYTES,
            SIDECAR_UNLISTED_PATH: b"unlisted-bytes-not-catalogued",
        },
    )
    return zip_bytes


def gen_tamper_040(seed: bytes, base_zip: bytes) -> bytes:
    """tamper/040 — derivation_version unknown. Manifest lists
    `c2pa-manifest@99`; verifier emits
    `interop_sidecar_derivation_version_unknown`. Wave 25 supports v1
    only; bumping to v2 is wire-breaking per ISC-06."""
    content_digest = domain_separated_sha256(CONTENT_DOMAIN, SIDECAR_BYTES)
    entry = build_positive_entry(content_digest, derivation_version=99)
    zip_bytes = build_export_zip(
        base_zip, seed,
        sidecar_entries=[entry],
        sidecar_files={SIDECAR_PATH: SIDECAR_BYTES},
    )
    return zip_bytes


def gen_tamper_044(seed: bytes, base_zip: bytes) -> bytes:
    """tamper/044 — missing sidecar. Manifest lists a dispatched entry;
    the named sidecar file is absent, so verifier emits
    `interop_sidecar_missing` before digest recomputation."""
    content_digest = domain_separated_sha256(CONTENT_DOMAIN, SIDECAR_BYTES)
    entry = build_positive_entry(content_digest)
    zip_bytes = build_export_zip(
        base_zip,
        seed,
        sidecar_entries=[entry],
        sidecar_files={},
    )
    return zip_bytes


# ---------------------------------------------------------------------------
# Tamper manifest.toml templates (one per fixture).
# ---------------------------------------------------------------------------


TAMPER_TEMPLATE = """\
id          = "tamper/{slug}"
op          = "tamper"
status      = "active"
description = \"\"\"{description}\"\"\"

[coverage]
tr_core = [{coverage_rows}]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = false
integrity_verified   = false
readability_verified = false
tamper_kind          = "{tamper_kind}"
"""


# ---------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------


def main() -> None:
    seed, _pubkey = load_seed_and_pubkey(KEY_ISSUER)
    base_zip = BASE_EXPORT_ZIP.read_bytes()

    # === export/014 (positive — export-op, byte-exact ZIP replay) ===
    zip_014, members_014, manifest_014 = gen_export_014(seed, base_zip)
    inputs_014: dict[str, bytes] = {
        "expected-export.zip": zip_014,
        "input-ledger-state.cbor": members_014.pop("__ledger_state__"),
    }
    # Ship each member as an individual file at the fixture root; the
    # conformance walker reads `input-ledger-state.cbor.members[*]` and
    # opens each path under the fixture dir.
    for relative, blob in members_014.items():
        # Members can be nested (e.g. `050-registries/<digest>.cbor` /
        # `interop-sidecars/c2pa-manifest/<file>`). Create parents
        # before writing.
        target = OUT_EXPORT_014 / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
    write_fixture(
        OUT_EXPORT_014,
        manifest_014,
        inputs_014,
    )
    derivation_014 = (
        "# `export/014-interop-sidecar-c2pa-manifest` derivation\n\n"
        "Wave 25 positive — c2pa-manifest@v1 dispatched verifier.\n\n"
        "Built by re-emitting `export/012-interop-sidecars-empty-list`'s\n"
        "manifest with `interop_sidecars: [<one c2pa-manifest@v1 entry>]`,\n"
        "adding the sidecar file at\n"
        "`interop-sidecars/c2pa-manifest/cert-wave25-001.c2pa`, and re-\n"
        "signing the manifest under `_keys/issuer-001.cose_key`.\n\n"
        "The sidecar bytes are a synthetic five-field Trellis assertion\n"
        "dCBOR map (mirrors `trellis-interop-c2pa::emit_c2pa_manifest_for_certificate`).\n"
        "For path-(b) digest-only verification, the wrapping format is\n"
        "irrelevant — the verifier only recomputes\n"
        "`SHA-256(trellis-content-v1, file-bytes)` and compares to\n"
        "`manifest.interop_sidecars[0].content_digest`.\n\n"
        "Op is `export` per the directory naming rule "
        "(`check-specs.py:check_vector_manifest_identity` requires the\n"
        "directory's first segment match `manifest.op`). The conformance\n"
        "walker rebuilds the ZIP byte-for-byte from\n"
        "`input-ledger-state.cbor` + per-member files; the result MUST\n"
        "equal `expected-export.zip` (Core §18.1 deterministic ZIP).\n"
        "Sidecar member at `interop-sidecars/c2pa-manifest/cert-wave25-001.c2pa`\n"
        "is included in the member list.\n\n"
        f"`zip_sha256 = {hashlib.sha256(zip_014).hexdigest()}`\n"
    )
    (OUT_EXPORT_014 / "derivation.md").write_text(derivation_014, encoding="utf-8")

    # === tamper/037 (content mismatch) ===
    zip_037 = gen_tamper_037(seed, base_zip)
    manifest_037 = TAMPER_TEMPLATE.format(
        slug="037-interop-sidecar-content-mismatch",
        description=(
            "Wave 25 — `interop_sidecar_content_mismatch`. Manifest lists "
            "one `c2pa-manifest@v1` entry whose `content_digest` is the "
            "SHA-256 (under `trellis-content-v1`) of the canonical sidecar "
            "bytes; the on-disk sidecar at "
            "`interop-sidecars/c2pa-manifest/cert-wave25-001.c2pa` has its "
            "last byte XOR-flipped. Phase-1 verifier emits "
            "`tamper_kind = \"interop_sidecar_content_mismatch\"`. Anchors "
            "TR-CORE-163 (digest recompute under domain tag)."
        ),
        coverage_rows='"TR-CORE-163"',
        tamper_kind="interop_sidecar_content_mismatch",
    )
    write_fixture(OUT_TAMPER_037, manifest_037, {"input-export.zip": zip_037})

    # === tamper/038 (kind unknown) ===
    zip_038 = gen_tamper_038(seed, base_zip)
    manifest_038 = TAMPER_TEMPLATE.format(
        slug="038-interop-sidecar-kind-unknown",
        description=(
            "Wave 25 — `interop_sidecar_kind_unknown`. Manifest lists one "
            "entry with `kind = \"made-up-kind\"` (not in the ADR 0008 "
            "closed registry of `scitt-receipt`, `vc-jose-cose-event`, "
            "`c2pa-manifest`, `did-key-view`). Phase-1 verifier emits "
            "`tamper_kind = \"interop_sidecar_kind_unknown\"` before any "
            "digest check runs. Anchors TR-CORE-164 (closed-registry gate)."
        ),
        coverage_rows='"TR-CORE-164"',
        tamper_kind="interop_sidecar_kind_unknown",
    )
    write_fixture(OUT_TAMPER_038, manifest_038, {"input-export.zip": zip_038})

    # === tamper/039 (unlisted file) ===
    zip_039 = gen_tamper_039(seed, base_zip)
    manifest_039 = TAMPER_TEMPLATE.format(
        slug="039-interop-sidecar-unlisted-file",
        description=(
            "Wave 25 — `interop_sidecar_unlisted_file`. Manifest lists ONE "
            "valid `c2pa-manifest@v1` entry with matching `content_digest`; "
            "the on-disk `interop-sidecars/` tree contains TWO files — the "
            "manifest-listed one plus a stray `stray.cbor` not catalogued "
            "in `manifest.interop_sidecars`. Phase-1 verifier emits "
            "`tamper_kind = \"interop_sidecar_unlisted_file\"` after the "
            "manifest walk completes (smuggled-sidecar attack surface). "
            "Anchors TR-CORE-165 (manifest-completeness gate)."
        ),
        coverage_rows='"TR-CORE-165"',
        tamper_kind="interop_sidecar_unlisted_file",
    )
    write_fixture(OUT_TAMPER_039, manifest_039, {"input-export.zip": zip_039})

    # === tamper/040 (derivation_version unknown) ===
    zip_040 = gen_tamper_040(seed, base_zip)
    manifest_040 = TAMPER_TEMPLATE.format(
        slug="040-interop-sidecar-derivation-version-unknown",
        description=(
            "Wave 25 — `interop_sidecar_derivation_version_unknown`. "
            "Manifest lists one `c2pa-manifest` entry with "
            "`derivation_version: 99`; Wave 25 supports v1 only. Phase-1 "
            "verifier emits "
            "`tamper_kind = \"interop_sidecar_derivation_version_unknown\"`. "
            "Bumping the derivation_version is wire-breaking per ISC-06; "
            "this fixture pins the verifier-side rejection. Anchors "
            "TR-CORE-166 (ISC-06 version pin)."
        ),
        coverage_rows='"TR-CORE-166"',
        tamper_kind="interop_sidecar_derivation_version_unknown",
    )
    write_fixture(OUT_TAMPER_040, manifest_040, {"input-export.zip": zip_040})

    # === tamper/044 (sidecar missing) ===
    zip_044 = gen_tamper_044(seed, base_zip)
    manifest_044 = TAMPER_TEMPLATE.format(
        slug="044-interop-sidecar-missing",
        description=(
            "Wave 31 — `interop_sidecar_missing`. Manifest lists one "
            "`c2pa-manifest@v1` entry with a valid `content_digest`, but "
            "the referenced "
            "`interop-sidecars/c2pa-manifest/cert-wave25-001.c2pa` member "
            "is absent from the export ZIP. Phase-1 verifier emits "
            "`tamper_kind = \"interop_sidecar_missing\"` before digest "
            "recomputation. Anchors TR-CORE-168 (listed-file presence gate)."
        ),
        coverage_rows='"TR-CORE-168"',
        tamper_kind="interop_sidecar_missing",
    )
    write_fixture(OUT_TAMPER_044, manifest_044, {"input-export.zip": zip_044})

    print("Wrote:")
    print(f"  {OUT_EXPORT_014.relative_to(ROOT)}/  zip_sha256={hashlib.sha256(zip_014).hexdigest()}")
    print(f"  {OUT_TAMPER_037.relative_to(ROOT)}/")
    print(f"  {OUT_TAMPER_038.relative_to(ROOT)}/")
    print(f"  {OUT_TAMPER_039.relative_to(ROOT)}/")
    print(f"  {OUT_TAMPER_040.relative_to(ROOT)}/")
    print(f"  {OUT_TAMPER_044.relative_to(ROOT)}/")


if __name__ == "__main__":
    main()
