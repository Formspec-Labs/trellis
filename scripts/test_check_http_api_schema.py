"""Unit tests for scripts/check-http-api-schema.py."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-http-api-schema.py"


def load_checker_module():
    spec = importlib.util.spec_from_file_location("check_http_api_schema", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load check-http-api-schema.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[assignment]
    return module


class TestCheckHttpApiSchema(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_checker_module()
        self.server_source = self.module.SERVER_PATH.read_text(encoding="utf-8")
        self.client_source = self.module.CLIENT_PATH.read_text(encoding="utf-8")
        self.schema = self.module.read_json(self.module.SCHEMA_PATH)

    def test_given_live_schema_when_check_defs_then_no_errors(self) -> None:
        errors: list[str] = []
        self.module.check_defs(self.schema, self.server_source, self.client_source, errors)
        self.assertEqual(errors, [])

    def test_given_wos_event_types_alias_when_parse_then_matches_kind_rs_table(self) -> None:
        literals = self.module.parse_wos_event_types(self.server_source)
        self.assertGreater(len(literals), 10)
        self.assertIn("wos.kernel.case_created", literals)
        self.assertEqual(literals[0], "wos.ai.capability_invocation")
        kind_text = self.module.WOS_EVENTS_KIND_PATH.read_text(encoding="utf-8")
        from_kind = self.module.parse_substrate_event_literals_from_kind_rs(kind_text)
        self.assertEqual(literals, from_kind)

    def test_given_profile_id_const_lock_when_check_defs_then_error_emitted(self) -> None:
        schema = self.module.read_json(self.module.SCHEMA_PATH)
        schema["$defs"]["VerificationReceipt"]["properties"]["profileId"]["const"] = 2
        errors: list[str] = []
        self.module.check_defs(schema, self.server_source, self.client_source, errors)
        self.assertIn(
            "VerificationReceipt.profileId must not const-lock a single global profile",
            errors,
        )

    def test_given_missing_client_route_fragment_when_check_operations_then_error_emitted(self) -> None:
        errors: list[str] = []
        client_source = self.client_source.replace("/v1/scopes/{}/events", "/removed")
        self.module.check_operations(self.schema, self.server_source, client_source, errors)
        self.assertTrue(
            any("trellis-service-client is missing route fragment" in error for error in errors),
            msg=errors,
        )

    def test_given_schema_missing_wos_event_when_check_defs_then_error_emitted(self) -> None:
        schema = self.module.read_json(self.module.SCHEMA_PATH)
        event_types = list(schema["$defs"]["EventType"]["enum"])
        event_types.remove("wos.kernel.case_created")
        schema["$defs"]["EventType"]["enum"] = event_types
        errors: list[str] = []
        self.module.check_defs(schema, self.server_source, self.client_source, errors)
        self.assertTrue(
            any("EventType enum drifted from trellis-server admitted literals" in error for error in errors),
            msg=errors,
        )

    def test_given_schema_drifted_registry_version_when_check_defs_then_error_emitted(
        self,
    ) -> None:
        schema = self.module.read_json(self.module.SCHEMA_PATH)
        schema["$defs"]["EventTypeRegistry"]["properties"]["registryVersion"]["const"] = (
            "synthetic-drift"
        )
        errors: list[str] = []
        self.module.check_defs(schema, self.server_source, self.client_source, errors)
        self.assertTrue(
            any("EventTypeRegistry.registryVersion drifted from server constant" in error for error in errors),
            msg=errors,
        )

    def test_given_server_missing_admitted_profile_when_check_defs_then_error_emitted(
        self,
    ) -> None:
        # DI-000/DI-003: assert the new AdmittedEvent.profile_id contract is
        # present (replaces the deleted profile_id_for_admitted_event check).
        server_source = self.server_source.replace("AdmittedEvent", "RetiredEnvelope")
        server_source = server_source.replace("profile_id: ProfileId", "profile_id: u64")
        errors: list[str] = []
        self.module.check_defs(self.schema, server_source, self.client_source, errors)
        self.assertTrue(
            any("AdmittedEvent.profile_id" in error for error in errors),
            msg=errors,
        )

    def test_given_openapi_operation_id_drift_when_check_openapi_operations_then_error_emitted(
        self,
    ) -> None:
        schema = {
            "x-trellis-http-api": {
                "operations": [
                    {
                        "operationId": "appendEvent",
                        "method": "POST",
                        "path": "/v1/scopes/{scope}/events",
                    }
                ]
            }
        }
        openapi = {
            "paths": {
                "/v1/scopes/{scope}/events": {
                    "post": {"operationId": "append_event"}
                }
            }
        }
        errors: list[str] = []
        self.module.check_openapi_operations(schema, openapi, errors)
        self.assertTrue(
            any("OpenAPI operationId mismatch" in error for error in errors),
            msg=errors,
        )

    def test_given_openapi_event_type_plain_string_when_check_openapi_event_type_enum_then_error(
        self,
    ) -> None:
        openapi = {
            "components": {
                "schemas": {
                    "SubstrateAppendBody": {
                        "properties": {"eventType": {"type": "string"}},
                    }
                }
            }
        }
        errors: list[str] = []
        self.module.check_openapi_event_type_enum(
            openapi, self.server_source, self.client_source, errors
        )
        self.assertTrue(
            any("must declare a string enum" in e for e in errors),
            msg=errors,
        )

    def test_given_openapi_event_type_enum_drift_when_check_openapi_event_type_enum_then_error(
        self,
    ) -> None:
        openapi = {
            "components": {
                "schemas": {
                    "SubstrateAppendBody": {
                        "properties": {
                            "eventType": {
                                "type": "string",
                                "enum": ["wos.kernel.case_created", "synthetic.extra.literal"],
                            }
                        }
                    }
                }
            }
        }
        errors: list[str] = []
        self.module.check_openapi_event_type_enum(
            openapi, self.server_source, self.client_source, errors
        )
        self.assertTrue(
            any("OpenAPI SubstrateAppendBody.eventType enum drifted" in e for e in errors),
            msg=errors,
        )


if __name__ == "__main__":
    unittest.main()
