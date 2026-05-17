"""Pinned byte-level helpers: dCBOR, §9.1 domain separation, §18.1 ZIP.

Every symbol here is a verbatim extraction of code that previously
appeared in two or more generators under
`fixtures/vectors/_generator/`. No spec interpretation lives in this
file — if you find yourself adding a hash construction that has a Core
§N prose citation, put it in the generator, not here.
"""

from __future__ import annotations

import hashlib
import zipfile
from typing import Any

import cbor2


# ---------------------------------------------------------------------------
# COSE header labels (RFC 9052 §3.1 + Core §7.4).
# ---------------------------------------------------------------------------

COSE_LABEL_ALG: int = 1
COSE_LABEL_KID: int = 4
# §7.4: Trellis-reserved label for suite_id in the COSE protected header.
# Must match `trellis_types::COSE_LABEL_SUITE_ID` in `crates/trellis-types`.
COSE_LABEL_SUITE_ID: int = -65537
# §7.4 / ADR 0109: Trellis-reserved label for substrate artifact_type.
# Must match `trellis_types::COSE_LABEL_ARTIFACT_TYPE` in `crates/trellis-types`.
COSE_LABEL_ARTIFACT_TYPE: int = -65538

# §7.4 / ADR 0109 closed substrate artifact_type values.
ARTIFACT_TYPE_EVENT: str = "event"
ARTIFACT_TYPE_CHECKPOINT: str = "checkpoint"
ARTIFACT_TYPE_MANIFEST: str = "manifest"

# §7.1 COSE algorithm value for EdDSA.
ALG_EDDSA: int = -8

# RFC 9052 §4.2 COSE_Sign1 tag.
CBOR_TAG_COSE_SIGN1: int = 18

# Phase-1 signature suite identifier (Core §7 suite registry).
SUITE_ID_PHASE_1: int = 1

# §18.1 fixed ZIP modification time (the DOS epoch minimum).
ZIP_FIXED_DATETIME: tuple[int, int, int, int, int, int] = (1980, 1, 1, 0, 0, 0)


# ---------------------------------------------------------------------------
# Core §5.1 dCBOR: RFC 8949 §4.2.2 canonical encoding.
# ---------------------------------------------------------------------------


def dcbor(value: Any) -> bytes:
    """Canonical CBOR encoding (Core §5.1, RFC 8949 §4.2.2)."""
    return cbor2.dumps(value, canonical=True)


# ---------------------------------------------------------------------------
# Core §9.1 domain-separated SHA-256.
# ---------------------------------------------------------------------------


def domain_separated_sha256(tag: str, *components: bytes) -> bytes:
    """§9.1 framing: SHA-256 over
    `len(tag)|u32be || tag || len(c0)|u32be || c0 || …`.

    Accepts one or more byte components so both the single-component
    callers (append, verify) and the multi-component manifest-digest
    caller (export) can share one helper.
    """
    tag_bytes = tag.encode("utf-8")
    buf = bytearray()
    buf += len(tag_bytes).to_bytes(4, "big")
    buf += tag_bytes
    for component in components:
        buf += len(component).to_bytes(4, "big")
        buf += component
    return hashlib.sha256(bytes(buf)).digest()


# ---------------------------------------------------------------------------
# Core §28 protobuf-pattern timestamp: [seconds, nanos].
# ---------------------------------------------------------------------------


def ts(seconds: int, nanos: int = 0) -> list:
    """Wrap a Unix-epoch timestamp as [seconds, nanos] per Core §28 CDDL.

    ADR 0069 D-2.1 protobuf-pattern wire format: every CBOR ``timestamp``
    site is ``[uint, uint .le 999999999]``.  Generators call ``ts(1745000000)``
    instead of bare ``1745000000``; the returned list encodes as a
    definite-length CBOR array under ``dcbor()``.
    """
    assert isinstance(seconds, int) and seconds >= 0
    assert isinstance(nanos, int) and 0 <= nanos <= 999_999_999
    return [seconds, nanos]


# ---------------------------------------------------------------------------
# Core §18.1 deterministic ZIP entry.
# ---------------------------------------------------------------------------


def deterministic_zipinfo(arcname: str) -> zipfile.ZipInfo:
    """Build a ZipInfo pinned to the §18.1 deterministic shape.

    §18.1 requires: STORED compression, no extra field, flag_bits=0,
    external_attr=0, fixed mod time. CPython's `ZipFile._open_to_write`
    overwrites a zero `external_attr` back to `0o600 << 16` before the
    central-directory entry is built, so generators MUST patch it back
    to 0 on every `zf.filelist` entry before close flushes the central
    directory. See `gen_export_001.py`/`gen_verify_negative_export_001.py` for the
    post-writestr patch.
    """
    info = zipfile.ZipInfo(filename=arcname, date_time=ZIP_FIXED_DATETIME)
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = 0
    info.extra = b""
    info.flag_bits = 0
    info.create_system = 0
    return info


def trellis_cli_verify_script_text() -> str:
    """Human-facing export verifier shim for active export fixtures."""
    return (
        "#!/bin/sh\n"
        "set -eu\n"
        "\n"
        "# Trellis export verifier invocation (§18.8).\n"
        "#\n"
        "# Pass the export ZIP path as the only argument; the operator CLI\n"
        "# verifies it through trellis-verify-wos.\n"
        "\n"
        "if [ \"$#\" -ne 1 ]; then\n"
        "  echo \"usage: $0 <export.zip>\" >&2\n"
        "  exit 2\n"
        "fi\n"
        "\n"
        "if command -v trellis-cli >/dev/null 2>&1; then\n"
        "  exec trellis-cli verify-export \"$1\"\n"
        "fi\n"
        "\n"
        "echo \"trellis-cli not found in PATH.\" >&2\n"
        "echo \"Run `trellis-cli verify-export $1`.\" >&2\n"
        "exit 2\n"
    )


def trellis_cli_verify_script() -> bytes:
    """Byte form of [`trellis_cli_verify_script_text`]."""
    return trellis_cli_verify_script_text().encode("utf-8")
