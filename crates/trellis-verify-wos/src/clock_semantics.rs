// Rust guideline compliant 2026-02-21
//! WOS clock semantic checks.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use ciborium::Value;
use serde_json::Value as JsonValue;
use trellis_types::{map_lookup_map, map_lookup_optional_value, map_lookup_text};
use trellis_verify::{DomainEvent, DomainExport, DomainFinding, Severity, TrellisTimestamp};

use crate::event_types::{
    OPEN_CLOCKS_EXPORT_EXTENSION, WOS_GOVERNANCE_CLOCK_RESOLVED_EVENT_TYPE,
    WOS_GOVERNANCE_CLOCK_STARTED_EVENT_TYPE,
};

const CLOCK_STARTED_RECORD_KIND: &str = "clockStarted";
const CLOCK_RESOLVED_RECORD_KIND: &str = "clockResolved";
const CLOCK_RESOLUTION_PAUSED: &str = "paused";
const OPEN_CLOCKS_MEMBER: &str = "open-clocks.json";

pub(crate) fn validate_clock_semantics(events: &[DomainEvent]) -> Vec<DomainFinding> {
    let mut active = BTreeMap::<String, ClockSegment>::new();
    let mut paused = BTreeMap::<String, ClockSegment>::new();
    let mut findings = Vec::new();

    for event in events {
        // Spec contract (`trellis/specs/wos-trellis-verification.md` §3): clock
        // semantics gate on `event_type`, not on payload shape. A non-clock
        // event whose payload happens to deserialize as a clock record MUST
        // NOT participate in segment validation.
        if event.event_type != WOS_GOVERNANCE_CLOCK_STARTED_EVENT_TYPE
            && event.event_type != WOS_GOVERNANCE_CLOCK_RESOLVED_EVENT_TYPE
        {
            continue;
        }
        let Some(payload) = event.payload.as_deref() else {
            continue;
        };
        let Ok(Some(clock_record)) = parse_clock_record(payload) else {
            continue;
        };
        match clock_record {
            ClockRecord::Started(started) => {
                if let Some(paused_segment) = paused.remove(&started.clock_id)
                    && (paused_segment.clock_kind != started.clock_kind
                        || paused_segment.calendar_ref != started.calendar_ref)
                {
                    findings.push(DomainFinding::new(
                        "clock_calendar_mismatch",
                        Some(event.canonical_event_hash),
                        Severity::Failure,
                        "resumed clock does not match paused clock kind or calendar reference",
                    ));
                }
                active.insert(
                    started.clock_id.clone(),
                    ClockSegment {
                        clock_kind: started.clock_kind,
                        calendar_ref: started.calendar_ref,
                    },
                );
            }
            ClockRecord::Resolved(resolved) => {
                if resolved.resolution == CLOCK_RESOLUTION_PAUSED {
                    if let Some(segment) = active.remove(&resolved.clock_id) {
                        paused.insert(resolved.clock_id, segment);
                    }
                } else {
                    active.remove(&resolved.clock_id);
                    paused.remove(&resolved.clock_id);
                }
            }
        }
    }
    findings
}

pub(crate) fn validate_open_clock_export(export: &DomainExport<'_>) -> Vec<DomainFinding> {
    if !export
        .manifest_extensions
        .contains_key(OPEN_CLOCKS_EXPORT_EXTENSION)
    {
        return Vec::new();
    }
    let Some(catalog_bytes) = export.members.get(OPEN_CLOCKS_MEMBER) else {
        return Vec::new();
    };
    let Ok(catalog) = parse_open_clocks_catalog(catalog_bytes) else {
        return Vec::new();
    };

    let sealed_at = catalog.sealed_at;
    catalog
        .open_clocks
        .into_iter()
        .filter(|row| row.computed_deadline < sealed_at)
        .map(|row| {
            DomainFinding::new(
                format!(
                    "open_clock_overdue:{}:{}",
                    row.clock_id,
                    hex_string(&row.origin_event_hash)
                ),
                Some(row.origin_event_hash),
                Severity::Advisory,
                "open statutory clock deadline is before export sealed_at",
            )
        })
        .collect()
}

#[derive(Clone, Debug)]
struct ClockSegment {
    clock_kind: String,
    calendar_ref: Option<String>,
}

struct OpenClockCatalog {
    open_clocks: Vec<OpenClockRow>,
    sealed_at: TrellisTimestamp,
}

struct OpenClockRow {
    clock_id: String,
    computed_deadline: TrellisTimestamp,
    origin_event_hash: [u8; 32],
}

enum ClockRecord {
    Started(ClockStartedRecord),
    Resolved(ClockResolvedRecord),
}

struct ClockStartedRecord {
    clock_id: String,
    clock_kind: String,
    calendar_ref: Option<String>,
}

struct ClockResolvedRecord {
    clock_id: String,
    resolution: String,
}

fn parse_clock_record(payload_bytes: &[u8]) -> Result<Option<ClockRecord>, String> {
    let value = decode_value(payload_bytes)?;
    let map = value
        .as_map()
        .ok_or_else(|| "clock record root is not a map".to_string())?;
    let record_kind = map_lookup_text(map, "recordKind").map_err(|error| error.to_string())?;
    match record_kind.as_str() {
        CLOCK_STARTED_RECORD_KIND => Ok(Some(ClockRecord::Started(parse_clock_started(map)?))),
        CLOCK_RESOLVED_RECORD_KIND => Ok(Some(ClockRecord::Resolved(parse_clock_resolved(map)?))),
        _ => Ok(None),
    }
}

fn parse_clock_started(map: &[(Value, Value)]) -> Result<ClockStartedRecord, String> {
    let data = map_lookup_map(map, "data").map_err(|error| error.to_string())?;
    Ok(ClockStartedRecord {
        clock_id: map_lookup_text(data, "clockId").map_err(|error| error.to_string())?,
        clock_kind: map_lookup_text(data, "clockKind").map_err(|error| error.to_string())?,
        calendar_ref: optional_text(data, "calendarRef")?,
    })
}

fn parse_clock_resolved(map: &[(Value, Value)]) -> Result<ClockResolvedRecord, String> {
    let data = map_lookup_map(map, "data").map_err(|error| error.to_string())?;
    Ok(ClockResolvedRecord {
        clock_id: map_lookup_text(data, "clockId").map_err(|error| error.to_string())?,
        resolution: map_lookup_text(data, "resolution").map_err(|error| error.to_string())?,
    })
}

fn optional_text(map: &[(Value, Value)], key: &str) -> Result<Option<String>, String> {
    let Some(value) = map_lookup_optional_value(map, key) else {
        return Ok(None);
    };
    match value {
        Value::Text(text) => Ok(Some(text.clone())),
        Value::Null => Ok(None),
        _ => Err(format!("{key} must be text or null")),
    }
}

fn decode_value(bytes: &[u8]) -> Result<Value, String> {
    ciborium::from_reader(bytes).map_err(|error| error.to_string())
}

fn parse_open_clocks_catalog(bytes: &[u8]) -> Result<OpenClockCatalog, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "catalog is not UTF-8".to_string())?;
    let value: JsonValue =
        serde_json::from_str(text).map_err(|error| format!("invalid JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "catalog root is not an object".to_string())?;
    let open_clock_values = object
        .get("open_clocks")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| "open_clocks is not an array".to_string())?;
    let sealed_at = parse_json_timestamp(
        object
            .get("sealed_at")
            .ok_or_else(|| "sealed_at is missing".to_string())?,
        "sealed_at",
    )?;

    let mut open_clocks = Vec::with_capacity(open_clock_values.len());
    for value in open_clock_values {
        let row = value
            .as_object()
            .ok_or_else(|| "open clock row is not an object".to_string())?;
        let origin_event_hash = parse_hex_32(
            row.get("origin_event_hash")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "origin_event_hash is not a string".to_string())?,
        )?;
        open_clocks.push(OpenClockRow {
            clock_id: row
                .get("clock_id")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "clock_id is not a string".to_string())?
                .to_string(),
            computed_deadline: parse_json_timestamp(
                row.get("computed_deadline")
                    .ok_or_else(|| "computed_deadline is missing".to_string())?,
                "computed_deadline",
            )?,
            origin_event_hash,
        });
    }

    Ok(OpenClockCatalog {
        open_clocks,
        sealed_at,
    })
}

fn parse_json_timestamp(value: &JsonValue, field: &str) -> Result<TrellisTimestamp, String> {
    let array = value
        .as_array()
        .ok_or_else(|| format!("{field} is not an array"))?;
    if array.len() != 2 {
        return Err(format!("{field} must have exactly two elements"));
    }
    let seconds = array[0]
        .as_u64()
        .ok_or_else(|| format!("{field}.seconds is not a uint"))?;
    let nanos_u64 = array[1]
        .as_u64()
        .ok_or_else(|| format!("{field}.nanos is not a uint"))?;
    let nanos = u32::try_from(nanos_u64).map_err(|_| format!("{field}.nanos out of u32 range"))?;
    if nanos > 999_999_999 {
        return Err(format!("{field}.nanos must be <= 999999999"));
    }
    Ok(TrellisTimestamp { seconds, nanos })
}

fn parse_hex_32(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex_decode(value)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "hex string must decode to 32 bytes".to_string())
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("hex string must have even length".to_string());
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("hex string contains a non-hex digit".to_string()),
    }
}

fn hex_string(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}
