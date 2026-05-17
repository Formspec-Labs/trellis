// Rust guideline compliant 2026-02-21
//! OpenAPI document generation for the Trellis substrate HTTP API (TWREF-086).

use axum::Json;
use serde::Serialize;
use stack_common_error::{ProblemJson, StackError};
use trellis_service_client::{
    AppendActor, ClientAttestation, ComputeContext, ComputeSensitivity, SubstrateAppendBody,
    SubstrateAppendResult, VerificationReceipt,
};
use utoipa::{OpenApi, ToSchema};

/// OpenAPI registry for the Trellis substrate service.
#[derive(Debug, OpenApi)]
#[openapi(
    info(
        title = "Trellis Substrate API",
        version = "1.0.0",
        description = "HTTP boundary for appending events, reading proof bundles, and retrieving registry projections from the Trellis substrate service.",
        license(name = "Apache-2.0"),
    ),
    servers(
        (url = "/", description = "Trellis service root."),
    ),
    paths(
        crate::http::append_event,
        crate::http::head_bundle,
        crate::http::pinned_bundle,
        crate::http::signing_key_registry,
        crate::http::event_type_registry,
        openapi_json,
    ),
    components(schemas(
        AppendActor,
        ClientAttestation,
        ComputeContext,
        ComputeSensitivity,
        EventTypeRegistryEntry,
        EventTypeRegistryView,
        OpenApiDocument,
        ProblemJson,
        SubstrateAppendBody,
        SubstrateAppendResult,
        VerificationReceipt,
    )),
    tags(
        (name = "events", description = "Append proof-bearing events into a Trellis scope."),
        (name = "bundles", description = "Read Trellis export bundles by scope and checkpoint."),
        (name = "registries", description = "Read registry snapshots bound into Trellis bundles."),
        (name = "meta", description = "API description endpoints."),
    ),
)]
pub struct TrellisServerOpenApi;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EventTypeRegistryEntry {
    pub(crate) event_type: String,
    pub(crate) schema_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EventTypeRegistryView {
    pub(crate) registry_version: String,
    pub(crate) event_types: Vec<EventTypeRegistryEntry>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct OpenApiDocument {
    pub(crate) openapi: String,
    pub(crate) info: serde_json::Value,
    pub(crate) paths: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) components: Option<serde_json::Value>,
}

/// Serves the OpenAPI document as JSON.
#[utoipa::path(
    get,
    path = "/openapi.json",
    responses(
        (status = 200, description = "OpenAPI specification document.", body = OpenApiDocument)
    ),
    tag = "meta",
    operation_id = "openapi_json",
)]
pub async fn openapi_json() -> Result<Json<serde_json::Value>, StackError> {
    serde_json::to_value(TrellisServerOpenApi::openapi())
        .map(Json)
        .map_err(|error| StackError::internal(format!("OpenAPI serialization failed: {error}")))
}

/// Asserts OpenAPI version, title, and substrate route entries on a JSON document.
///
/// Intended for contract tests (library and integration) so HTTP-served and
/// derived documents stay aligned.
pub fn assert_trellis_openapi_shape(doc: &serde_json::Value) {
    assert_eq!(doc["openapi"], "3.1.0");
    assert_eq!(doc["info"]["title"], "Trellis Substrate API");
    for (path, method) in [
        ("/openapi.json", "get"),
        ("/v1/scopes/{scope}/events", "post"),
        ("/v1/scopes/{scope}/bundles/head", "get"),
        ("/v1/scopes/{scope}/bundles/{checkpointDigest}", "get"),
        ("/v1/scopes/{scope}/registries/signing-keys", "get"),
        ("/v1/scopes/{scope}/registries/event-types", "get"),
    ] {
        assert!(
            doc["paths"][path].get(method).is_some(),
            "OpenAPI must include {method} {path}"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;
    use utoipa::OpenApi as _;
    use wos_events::WOS_CANONICAL_EVENT_LITERALS;

    use crate::FORMSPEC_RESPONSE_SUBMITTED;

    use super::*;

    #[test]
    fn openapi_append_contract_matches_json_schema() {
        let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../specs/trellis-http-api.schema.json");
        let schema: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(schema_path).expect("schema file")).unwrap();
        let openapi = serde_json::to_value(TrellisServerOpenApi::openapi()).unwrap();
        let schema_events = schema["$defs"]["EventType"]["enum"]
            .as_array()
            .expect("schema EventType enum");
        let append_body_schema = &openapi["components"]["schemas"]["SubstrateAppendBody"];
        assert!(
            append_body_schema["properties"].get("eventType").is_some(),
            "OpenAPI SubstrateAppendBody must declare eventType"
        );
        let openapi_enum = append_body_schema["properties"]["eventType"]["enum"]
            .as_array()
            .expect("OpenAPI eventType must be a string enum (TWREF-094)");
        let openapi_sorted = {
            let mut v: Vec<String> = openapi_enum
                .iter()
                .map(|x| x.as_str().expect("event type literal").to_string())
                .collect();
            v.sort();
            v
        };
        let schema_sorted = {
            let mut v: Vec<String> = schema_events
                .iter()
                .map(|x| x.as_str().expect("event type literal").to_string())
                .collect();
            v.sort();
            v
        };
        assert_eq!(
            openapi_sorted, schema_sorted,
            "OpenAPI eventType enum must match trellis-http-api.schema.json EventType"
        );
        for event_type in schema_events {
            let literal = event_type.as_str().expect("event type literal");
            assert!(
                WOS_CANONICAL_EVENT_LITERALS.contains(&literal)
                    || literal == FORMSPEC_RESPONSE_SUBMITTED,
                "schema EventType enum must only list admitted server literals"
            );
        }
        let schema_artifact = &schema["$defs"]["VerificationReceipt"]["properties"]["artifactType"];
        let openapi_artifact =
            &openapi["components"]["schemas"]["VerificationReceipt"]["properties"]["artifactType"];
        assert_eq!(
            openapi_artifact["type"], "string",
            "OpenAPI VerificationReceipt.artifactType must be string"
        );
        assert_eq!(
            schema_artifact["enum"],
            json!(["event", "checkpoint", "manifest"]),
            "JSON schema must enumerate closed artifactType values"
        );
        let schema_verified = &schema["$defs"]["VerificationReceipt"]["properties"]["verified"];
        assert_eq!(
            schema_verified["type"], "boolean",
            "VerificationReceipt.verified must be boolean in JSON schema"
        );
    }

    #[test]
    fn openapi_registry_declares_trellis_append_response_shape() {
        let doc = serde_json::to_value(TrellisServerOpenApi::openapi()).unwrap();
        assert_trellis_openapi_shape(&doc);
        let schemas = doc["components"]["schemas"].as_object().unwrap();
        let append_properties = schemas["SubstrateAppendResult"]["properties"]
            .as_object()
            .unwrap();
        for property in [
            "eventId",
            "sequence",
            "canonicalEventHash",
            "checkpointRef",
            "bundleRef",
            "verificationReceipt",
        ] {
            assert!(
                append_properties.contains_key(property),
                "SubstrateAppendResult must expose {property}"
            );
        }
        assert!(
            schemas
                .get("VerificationReceipt")
                .and_then(|schema| schema["properties"].as_object())
                .is_some_and(|properties| {
                    ["verified", "artifactType", "eventType"]
                        .iter()
                        .all(|property| properties.contains_key(*property))
                }),
            "VerificationReceipt schema must expose verified/artifactType/eventType"
        );
    }
}
