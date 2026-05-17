// Rust guideline compliant 2026-02-21
//! Ensures OpenAPI types are reachable via `trellis_server::openapi` (TWREF-086).

use trellis_server::openapi::{TrellisServerOpenApi, assert_trellis_openapi_shape};
use utoipa::OpenApi as _;

#[test]
fn trellis_openapi_public_module_surface() {
    let doc = serde_json::to_value(TrellisServerOpenApi::openapi()).expect("openapi json");
    assert_trellis_openapi_shape(&doc);
}
