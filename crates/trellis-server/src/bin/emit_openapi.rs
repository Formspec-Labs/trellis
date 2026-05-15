//! Emit the Trellis substrate OpenAPI document.

use std::process::ExitCode;

use trellis_server::TrellisServerOpenApi;
use utoipa::OpenApi as _;

fn main() -> ExitCode {
    let api = TrellisServerOpenApi::openapi();
    match api.to_pretty_json() {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("emit-openapi: OpenAPI serialization failed: {error}");
            ExitCode::from(1)
        }
    }
}
