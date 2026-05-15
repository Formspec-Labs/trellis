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
CLIENT_PATH = ROOT / "crates" / "trellis-service-client" / "src" / "lib.rs"

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


def parse_wos_event_types(source: str) -> list[str]:
    match = re.search(
        r"const WOS_EVENT_TYPES: &\[&str\] = &\[(?P<body>.*?)\];",
        source,
        flags=re.S,
    )
    if not match:
        raise ValueError("could not find WOS_EVENT_TYPES")
    return re.findall(r'"([^"]+)"', match.group("body"))


def normalize_axum_path(path: str) -> str:
    return path.replace("{checkpoint_digest}", "{checkpointDigest}")


def parse_router_paths(source: str) -> set[str]:
    return {normalize_axum_path(path) for path in re.findall(r'\.route\(\s*"([^"]+)"', source)}


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

    router_paths = parse_router_paths(server_source)
    expected_paths = {path for _, path in EXPECTED_OPERATIONS.values()}
    if not expected_paths.issubset(router_paths):
        missing = sorted(expected_paths - router_paths)
        errors.append(f"server router is missing schema paths: {missing}")

    for path, fragment in CLIENT_ROUTE_FRAGMENTS.items():
        if fragment not in client_source:
            errors.append(f"trellis-service-client is missing route fragment for {path}: {fragment}")


def check_defs(schema: dict, server_source: str, errors: list[str]) -> None:
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

    server_events = parse_wos_event_types(server_source)
    formspec_event = parse_const_str(server_source, "FORMSPEC_RESPONSE_SUBMITTED")
    expected_events = server_events + [formspec_event]
    schema_events = defs["EventType"].get("enum")
    if schema_events != expected_events:
        errors.append(
            "EventType enum drifted from trellis-server admitted literals: "
            f"expected {expected_events}, got {schema_events}"
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

    if "profile_id_for_admitted_event" not in server_source:
        errors.append("trellis-server must define profile_id_for_admitted_event dispatch")
    schema_profile_id = (
        defs["VerificationReceipt"]
        .get("properties", {})
        .get("profileId", {})
    )
    if schema_profile_id.get("const") is not None:
        errors.append(
            "VerificationReceipt.profileId must not const-lock a single global profile"
        )
    if schema_profile_id.get("enum") != [1, 2]:
        errors.append(
            "VerificationReceipt.profileId must allow WOS profile 1 and Formspec profile 2"
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
        check_defs(schema, server_source, errors)
        check_operations(schema, server_source, client_source, errors)
        openapi = emit_openapi_document(errors)
        if openapi is not None:
            check_openapi_operations(schema, openapi, errors)
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
        f"{operation_count} operations, {event_count} WOS event literals."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
