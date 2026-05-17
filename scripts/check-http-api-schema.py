#!/usr/bin/env python3
"""Check the Trellis HTTP API schema against the live service wire.

Uses ``cargo run`` to emit OpenAPI; in CI, reuse a warm ``target/`` (or sccache)
so repeat runs do not pay full link cost on every invocation.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "specs" / "trellis-http-api.schema.json"
SERVER_PATH = ROOT / "crates" / "trellis-server" / "src" / "lib.rs"
# TWREF-086: Axum `.route(` calls live in `http.rs`; `lib.rs` keeps admission/constants.
HTTP_ROUTER_PATH = ROOT / "crates" / "trellis-server" / "src" / "http.rs"
CLIENT_PATH = ROOT / "crates" / "trellis-service-client" / "src" / "lib.rs"
# Sibling `work-spec/` at stack root (TWREF-017): substrate literals authored once in kind.rs.
WOS_EVENTS_KIND_PATH = (
    ROOT.parent / "work-spec" / "crates" / "wos-events" / "src" / "provenance" / "kind.rs"
)

EXPECTED_OPERATIONS = {
    "appendEvent": ("POST", "/v1/scopes/{scope}/events"),
    "getHeadBundle": ("GET", "/v1/scopes/{scope}/bundles/head"),
    "getBundleByCheckpointDigest": ("GET", "/v1/scopes/{scope}/bundles/{checkpointDigest}"),
    "getSigningKeyRegistry": ("GET", "/v1/scopes/{scope}/registries/signing-keys"),
    "getEventTypeRegistry": ("GET", "/v1/scopes/{scope}/registries/event-types"),
}

EXPECTED_TENANT_HEADERS = {
    "wos": [
        "x-wos-tenant-id",
        "x-wos-workspace-id",
        "x-wos-environment-id",
        "x-wos-cell-id",
    ],
    "formspec": [
        "x-formspec-tenant-id",
        "x-formspec-workspace-id",
        "x-formspec-environment-id",
        "x-formspec-cell-id",
    ],
}

CLIENT_ROUTE_FRAGMENTS = {
    "/v1/scopes/{scope}/events": "/v1/scopes/{}/events",
    "/v1/scopes/{scope}/bundles/head": "/v1/scopes/{}/bundles/head",
    "/v1/scopes/{scope}/bundles/{checkpointDigest}": "/v1/scopes/{}/bundles/{}",
    "/v1/scopes/{scope}/registries/signing-keys": "/v1/scopes/{}/registries/signing-keys",
    "/v1/scopes/{scope}/registries/event-types": "/v1/scopes/{}/registries/event-types",
}


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_const_str(source: str, name: str) -> str:
    match = re.search(rf'const {name}: &str = "([^"]+)";', source)
    if not match:
        raise ValueError(f"could not find const {name}")
    return match.group(1)


def parse_const_u64(source: str, name: str) -> int:
    match = re.search(rf"const {name}: u64 = ([0-9]+);", source)
    if not match:
        raise ValueError(f"could not find const {name}")
    return int(match.group(1))


def parse_formspec_append_event_literal(client_source: str) -> str:
    """Read FORMSPEC_APPEND_EVENT_TYPE_LITERAL from trellis-service-client (single string SOT)."""
    patterns = (
        r'pub const FORMSPEC_APPEND_EVENT_TYPE_LITERAL: &str = "([^"]+)";',
        r"pub const FORMSPEC_APPEND_EVENT_TYPE_LITERAL: &'static str = \"([^\"]+)\";",
    )
    for pat in patterns:
        match = re.search(pat, client_source)
        if match:
            return match.group(1)
    raise ValueError(
        "could not find pub const FORMSPEC_APPEND_EVENT_TYPE_LITERAL in trellis-service-client"
    )


def expected_admitted_event_types(server_source: str, client_source: str) -> list[str]:
    """Sorted comparison uses these lists; order here follows server macro + Formspec suffix."""
    return parse_wos_event_types(server_source) + [parse_formspec_append_event_literal(client_source)]


def parse_substrate_event_literals_from_kind_rs(kind_source: str) -> list[str]:
    """Read literals from define_canonical_substrate_events! { ... } (authoritative table)."""
    marker = "define_canonical_substrate_events!"
    start = kind_source.find(marker)
    if start == -1:
        raise ValueError(f"{marker} not found in wos-events provenance/kind.rs")
    brace_open = kind_source.find("{", start)
    if brace_open == -1:
        raise ValueError("macro invocation `{` not found after define_canonical_substrate_events!")
    depth = 0
    body_end = -1
    for idx in range(brace_open, len(kind_source)):
        char = kind_source[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                body_end = idx
                break
    if body_end == -1:
        raise ValueError("unterminated define_canonical_substrate_events! block in kind.rs")
    body = kind_source[brace_open + 1 : body_end]
    literals = re.findall(r'"([^"]+)"\s*=>', body)
    if not literals:
        raise ValueError("no substrate literals parsed from kind.rs macro body")
    return literals


def parse_wos_event_types(_server_source: str) -> list[str]:
    """Resolve admitted WOS event-type literals for schema drift checks.

    After Trellis DI-001 the in-server `WOS_EVENT_TYPES` alias is gone;
    the canonical literal table lives in `wos-events::SUBSTRATE_CANONICAL_EVENT_LITERALS`
    and is re-exported by `trellis-admission-wos::WOS_CANONICAL_EVENT_LITERALS`.
    Schema drift checks parse the literals directly from the
    `define_canonical_substrate_events!` macro in `kind.rs`.
    """
    if not WOS_EVENTS_KIND_PATH.is_file():
        raise ValueError(
            "wos-events canonical literal table not found at "
            f"{WOS_EVENTS_KIND_PATH} (expected stack checkout with sibling work-spec/)"
        )
    return parse_substrate_event_literals_from_kind_rs(
        WOS_EVENTS_KIND_PATH.read_text(encoding="utf-8")
    )


def normalize_axum_path(path: str) -> str:
    return path.replace("{checkpoint_digest}", "{checkpointDigest}")


def parse_router_paths(source: str) -> set[str]:
    return {normalize_axum_path(path) for path in re.findall(r'\.route\(\s*"([^"]+)"', source)}


def trellis_server_router_paths(lib_rs: str) -> set[str]:
    paths = parse_router_paths(lib_rs)
    if HTTP_ROUTER_PATH.is_file():
        paths |= parse_router_paths(HTTP_ROUTER_PATH.read_text(encoding="utf-8"))
    return paths


def normalize_openapi_path(path: str) -> str:
    return path.replace("{checkpoint_digest}", "{checkpointDigest}")


def require_defs(schema: dict, errors: list[str], names: list[str]) -> dict:
    defs = schema.get("$defs")
    if not isinstance(defs, dict):
        errors.append("schema is missing $defs")
        return {}
    for name in names:
        if name not in defs:
            errors.append(f"schema is missing $defs.{name}")
    return defs


def check_operations(schema: dict, server_source: str, client_source: str, errors: list[str]) -> None:
    meta = schema.get("x-trellis-http-api")
    if not isinstance(meta, dict):
        errors.append("schema is missing x-trellis-http-api metadata")
        return

    if meta.get("tenantHeaderSets") != EXPECTED_TENANT_HEADERS:
        errors.append("tenantHeaderSets drifted from stack-common HeaderConfig")

    operations = meta.get("operations")
    if not isinstance(operations, list):
        errors.append("x-trellis-http-api.operations must be a list")
        return

    by_id = {operation.get("operationId"): operation for operation in operations}
    if set(by_id) != set(EXPECTED_OPERATIONS):
        errors.append(
            "operationId set mismatch: "
            f"expected {sorted(EXPECTED_OPERATIONS)}, got {sorted(by_id)}"
        )
        return

    for operation_id, (method, path) in EXPECTED_OPERATIONS.items():
        operation = by_id[operation_id]
        if operation.get("method") != method:
            errors.append(f"{operation_id}: method must be {method}")
        if operation.get("path") != path:
            errors.append(f"{operation_id}: path must be {path}")
        if operation.get("tenantScopeRequired") is not True:
            errors.append(f"{operation_id}: tenantScopeRequired must be true")

    append = by_id["appendEvent"]
    if append.get("idempotencyHeaderMustEqualBodyField") != "idempotencyKey":
        errors.append("appendEvent must bind idempotency-key header to body idempotencyKey")
    if "idempotency-key" not in append.get("requiredHeaders", []):
        errors.append("appendEvent must require idempotency-key header")

    router_paths = trellis_server_router_paths(server_source)
    expected_paths = {path for _, path in EXPECTED_OPERATIONS.values()}
    if not expected_paths.issubset(router_paths):
        missing = sorted(expected_paths - router_paths)
        errors.append(f"server router is missing schema paths: {missing}")

    for path, fragment in CLIENT_ROUTE_FRAGMENTS.items():
        if fragment not in client_source:
            errors.append(f"trellis-service-client is missing route fragment for {path}: {fragment}")


def check_defs(schema: dict, server_source: str, client_source: str, errors: list[str]) -> None:
    defs = require_defs(
        schema,
        errors,
        [
            "EventType",
            "EventTypeRegistry",
            "EventTypeRegistryEntry",
            "SubstrateAppendBody",
            "SubstrateAppendResult",
            "VerificationReceipt",
            "ProblemJson",
        ],
    )
    if not defs:
        return

    expected_events = expected_admitted_event_types(server_source, client_source)
    schema_events = defs["EventType"].get("enum")
    # Ordering is not normative: macro table order may differ from schema enum order.
    if sorted(schema_events or []) != sorted(expected_events):
        errors.append(
            "EventType enum drifted from trellis-server admitted literals: "
            f"expected {sorted(expected_events)}, got {sorted(schema_events or [])}"
        )
    if len(schema_events or []) != len(set(schema_events or [])):
        errors.append("EventType enum contains duplicate values")

    registry_version = parse_const_str(server_source, "EVENT_TYPE_REGISTRY_VERSION")
    schema_registry_version = (
        defs["EventTypeRegistry"]
        .get("properties", {})
        .get("registryVersion", {})
        .get("const")
    )
    if schema_registry_version != registry_version:
        errors.append(
            "EventTypeRegistry.registryVersion drifted from server constant: "
            f"expected {registry_version}, got {schema_registry_version}"
        )

    # ADR 0109: admission returns substrate artifact type, not an integer
    # dispatch field. Assert the new contract instead.
    if "artifact_type: ArtifactType" not in server_source and "AdmittedEvent" not in server_source:
        errors.append(
            "trellis-server must consume AdmittedEvent.artifact_type (ADR 0109); "
            "previous integer dispatch was retired"
        )
    schema_artifact_type = (
        defs["VerificationReceipt"]
        .get("properties", {})
        .get("artifactType", {})
    )
    if schema_artifact_type.get("const") is not None:
        errors.append(
            "VerificationReceipt.artifactType must not const-lock a single value"
        )
    if schema_artifact_type.get("enum") != ["event", "checkpoint", "manifest"]:
        errors.append(
            "VerificationReceipt.artifactType must enumerate event/checkpoint/manifest"
        )
    schema_verified = (
        defs["VerificationReceipt"]
        .get("properties", {})
        .get("verified", {})
    )
    if schema_verified.get("type") != "boolean":
        errors.append("VerificationReceipt.verified must be type boolean (not const-locked)")

    append_required = set(defs["SubstrateAppendBody"].get("required", []))
    expected_append_required = {
        "eventType",
        "idempotencyKey",
        "actor",
        "payload",
        "computeContext",
    }
    if append_required != expected_append_required:
        errors.append(
            "SubstrateAppendBody required fields mismatch: "
            f"expected {sorted(expected_append_required)}, got {sorted(append_required)}"
        )

    result_required = set(defs["SubstrateAppendResult"].get("required", []))
    expected_result_required = {
        "eventId",
        "sequence",
        "canonicalEventHash",
        "checkpointRef",
        "bundleRef",
        "verificationReceipt",
    }
    if result_required != expected_result_required:
        errors.append(
            "SubstrateAppendResult required fields mismatch: "
            f"expected {sorted(expected_result_required)}, got {sorted(result_required)}"
        )


def extract_openapi_substrate_append_event_type_enum(openapi: dict) -> list[str] | None:
    """Return admitted `eventType` enum values from emitted OpenAPI (utoipa), if present."""
    schemas = openapi.get("components", {}).get("schemas", {})
    if not isinstance(schemas, dict):
        return None
    substrate = schemas.get("SubstrateAppendBody")
    if not isinstance(substrate, dict):
        return None
    props = substrate.get("properties", {})
    if not isinstance(props, dict):
        return None
    event_type = props.get("eventType")
    if not isinstance(event_type, dict):
        return None
    raw = event_type.get("enum")
    if not isinstance(raw, list):
        return None
    return [str(x) for x in raw]


def check_openapi_event_type_enum(
    openapi: dict, server_source: str, client_source: str, errors: list[str]
) -> None:
    expected = expected_admitted_event_types(server_source, client_source)
    openapi_vals = extract_openapi_substrate_append_event_type_enum(openapi)
    if openapi_vals is None:
        errors.append(
            "OpenAPI SubstrateAppendBody.eventType must declare a string enum of admitted literals "
            "(TWREF-094 drift guard)"
        )
        return
    if sorted(openapi_vals) != sorted(expected):
        errors.append(
            "OpenAPI SubstrateAppendBody.eventType enum drifted from admitted literals "
            "(wos-events substrate registry + FORMSPEC_APPEND_EVENT_TYPE_LITERAL): "
            f"expected {sorted(expected)}, got {sorted(openapi_vals)}"
        )
    if len(openapi_vals) != len(set(openapi_vals)):
        errors.append("OpenAPI SubstrateAppendBody.eventType enum contains duplicate values")


def check_openapi_append_contract(errors: list[str]) -> None:
    result = subprocess.run(
        [
            "cargo",
            "test",
            "-p",
            "trellis-server",
            "openapi_append_contract_matches_json_schema",
            "--",
            "--quiet",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        errors.append(f"OpenAPI append contract drift (run cargo test -p trellis-server): {detail}")


def emit_openapi_document(errors: list[str]) -> dict | None:
    result = subprocess.run(
        ["cargo", "run", "-p", "trellis-server", "--bin", "emit_openapi", "--quiet"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        errors.append(f"OpenAPI emit failed (run cargo run -p trellis-server --bin emit_openapi): {detail}")
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        errors.append(f"OpenAPI emit produced invalid JSON: {exc}")
        return None


def check_openapi_operations(schema: dict, openapi: dict, errors: list[str]) -> None:
    meta = schema.get("x-trellis-http-api")
    operations = meta.get("operations") if isinstance(meta, dict) else None
    if not isinstance(operations, list):
        errors.append("cannot compare OpenAPI operations: schema x-trellis-http-api.operations missing")
        return

    paths = openapi.get("paths")
    if not isinstance(paths, dict):
        errors.append("cannot compare OpenAPI operations: OpenAPI document is missing paths")
        return

    for operation in operations:
        operation_id = operation.get("operationId")
        method = operation.get("method")
        path = operation.get("path")
        if not isinstance(operation_id, str) or not isinstance(method, str) or not isinstance(path, str):
            errors.append("cannot compare OpenAPI operations: invalid operation entry in schema metadata")
            continue
        method_key = method.lower()
        path_item = paths.get(path) or paths.get(normalize_openapi_path(path))
        if not isinstance(path_item, dict):
            errors.append(f"OpenAPI missing operation for {method} {path}")
            continue
        operation_doc = path_item.get(method_key)
        if not isinstance(operation_doc, dict):
            errors.append(f"OpenAPI missing method entry for {method} {path}")
            continue
        openapi_operation_id = operation_doc.get("operationId")
        if openapi_operation_id != operation_id:
            errors.append(
                f"OpenAPI operationId mismatch for {method} {path}: "
                f"expected {operation_id}, got {openapi_operation_id}"
            )


def main() -> int:
    errors: list[str] = []
    try:
        schema = read_json(SCHEMA_PATH)
        server_source = SERVER_PATH.read_text(encoding="utf-8")
        client_source = CLIENT_PATH.read_text(encoding="utf-8")
        check_defs(schema, server_source, client_source, errors)
        check_operations(schema, server_source, client_source, errors)
        openapi = emit_openapi_document(errors)
        if openapi is not None:
            check_openapi_operations(schema, openapi, errors)
            check_openapi_event_type_enum(openapi, server_source, client_source, errors)
        check_openapi_append_contract(errors)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        errors.append(str(exc))

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    event_count = len(schema["$defs"]["EventType"]["enum"])
    operation_count = len(schema["x-trellis-http-api"]["operations"])
    print(
        "Trellis HTTP API schema OK: "
        f"{operation_count} operations, {event_count} admitted EventType literals (schema + OpenAPI)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
