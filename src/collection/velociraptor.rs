//! Velociraptor offline collections: `collection_context.json` (what was
//! requested, how each query ended), `log.json` (the collection log, one
//! JSON row per line), `uploads.json` (every file stored) and
//! `client_info.json` (the collector version).
//!
//! Field names and codes follow Velociraptor's `ArtifactCollectorContext`
//! and `VeloStatus` protobuf messages; older versions write enums as
//! numbers, so both numbers and names are accepted.

use std::collections::HashSet;

use common::json::{self, Json};
use common::time::Ts;

use super::{CollectionLog, CollectorFiles, Failure, LogLine, Outcome, PartialFile};
use crate::layout::LayoutKind;

const CONTEXT: &str = "collection_context.json";
const LOG: &str = "log.json";
const UPLOADS: &str = "uploads.json";
const CLIENT_INFO: &str = "client_info.json";
/// `ArtifactCollectorContext.State`.
const STATE_FINISHED: i64 = 2;
const STATE_ERROR: i64 = 3;
/// `VeloStatus.ReturnedStatus.GENERIC_ERROR`.
const STATUS_GENERIC_ERROR: i64 = 10;
/// Sparse uploads come with an index row of this type.
const SPARSE_INDEX: &str = "idx";

pub(super) fn read(files: &CollectorFiles<'_>) -> CollectionLog {
    let mut log = CollectionLog::new(LayoutKind::Velociraptor);
    if let Some(info) = read_json(files, CLIENT_INFO, &mut log) {
        log.version = text(&info, "Version");
    }
    if let Some(context) = read_json(files, CONTEXT, &mut log) {
        read_context(&context, &mut log);
    }
    if let Some(rows) = read_rows(files, LOG, &mut log) {
        read_log(&rows, &mut log);
    }
    if let Some(rows) = read_rows(files, UPLOADS, &mut log) {
        read_uploads(&rows, &mut log);
    }
    log
}

fn read_context(context: &Json, log: &mut CollectionLog) {
    log.started = context
        .get("create_time")
        .and_then(Json::as_i64)
        .map(epoch_time);
    let status = text(context, "status").unwrap_or_default();
    log.outcome = match enum_value(
        context.get("state"),
        &[("FINISHED", STATE_FINISHED), ("ERROR", STATE_ERROR)],
    ) {
        Some(STATE_FINISHED) if status.is_empty() => Outcome::Completed,
        Some(STATE_FINISHED | STATE_ERROR) => Outcome::Failed(status),
        _ => Outcome::Unknown,
    };
    log.requested = strings(context.get("request").and_then(|r| r.get("artifacts")));
    for stats in context
        .get("query_stats")
        .and_then(Json::as_array)
        .unwrap_or_default()
    {
        let status = enum_value(
            stats.get("status"),
            &[("GENERIC_ERROR", STATUS_GENERIC_ERROR)],
        );
        if status == Some(STATUS_GENERIC_ERROR) {
            let names = strings(stats.get("names_with_response"));
            let item = text(stats, "Artifact")
                .or_else(|| names.first().cloned())
                .unwrap_or_else(|| "(unnamed query)".to_owned());
            log.failed.push(Failure {
                item,
                reason: text(stats, "error_message").unwrap_or_default(),
            });
        }
    }
    // Results are named "Artifact" or "Artifact/Source".
    let with_results: HashSet<String> = strings(context.get("artifacts_with_results"))
        .iter()
        .map(|name| name.split('/').next().unwrap_or(name).to_owned())
        .collect();
    let failed: HashSet<&str> = log.failed.iter().map(|f| f.item.as_str()).collect();
    log.without_results = log
        .requested
        .iter()
        .filter(|name| !with_results.contains(*name) && !failed.contains(name.as_str()))
        .cloned()
        .collect();
}

fn read_log(rows: &[Json], log: &mut CollectionLog) {
    for row in rows {
        let level = text(row, "level").unwrap_or_default();
        let line = || LogLine {
            time: row
                .get("_ts")
                .and_then(Json::as_i64)
                .map(Ts::from_unix_seconds),
            message: text(row, "message").unwrap_or_default().trim().to_owned(),
        };
        if level.eq_ignore_ascii_case("ERROR") {
            log.log_error(line());
        } else if level.eq_ignore_ascii_case("WARN") || level.eq_ignore_ascii_case("WARNING") {
            log.warning_count += 1;
        }
    }
}

fn read_uploads(rows: &[Json], log: &mut CollectionLog) {
    let components = |row: &Json| strings(row.get("_Components")).join("/");
    let sparse: HashSet<String> = rows
        .iter()
        .filter(|row| text(row, "Type").as_deref() == Some(SPARSE_INDEX))
        .map(components)
        .collect();
    for row in rows
        .iter()
        .filter(|row| text(row, "Type").as_deref() != Some(SPARSE_INDEX))
    {
        log.files_recorded += 1;
        let expected = row.get("file_size").and_then(Json::as_u64).unwrap_or(0);
        let stored = row
            .get("uploaded_size")
            .and_then(Json::as_u64)
            .unwrap_or(expected);
        let path = components(row);
        if stored < expected && !sparse.contains(&path) {
            log.partial.push(PartialFile {
                path,
                expected,
                stored,
            });
        }
    }
}

/// Velociraptor writes `create_time` in nanoseconds in offline collections
/// and microseconds on the server; seconds appear in older exports.
fn epoch_time(value: i64) -> Ts {
    const NANOS: i64 = 100_000_000_000_000_000; // after 1973 in ns
    const MICROS: i64 = 100_000_000_000_000; // after 1973 in µs
    if value >= NANOS {
        Ts::from_unix_nanos(value)
    } else if value >= MICROS {
        Ts::from_unix_micros(value)
    } else {
        Ts::from_unix_seconds(value)
    }
}

/// An enum written as a number or as its name.
fn enum_value(value: Option<&Json>, names: &[(&str, i64)]) -> Option<i64> {
    let value = value?;
    value.as_i64().or_else(|| {
        let name = value.as_str()?;
        names
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|&(_, number)| number)
    })
}

fn text(object: &Json, name: &str) -> Option<String> {
    object
        .get(name)
        .and_then(Json::as_str)
        .map(str::to_owned)
        .filter(|s| !s.is_empty())
}

fn strings(value: Option<&Json>) -> Vec<String> {
    value
        .and_then(Json::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(Json::as_str)
        .map(str::to_owned)
        .collect()
}

fn read_json(files: &CollectorFiles<'_>, name: &str, log: &mut CollectionLog) -> Option<Json> {
    let text = files.read_text(files.find(name)?, log)?;
    let parsed = json::parse(&text).ok();
    if parsed.is_none() {
        log.gaps.push(format!("{name}: not valid JSON"));
    }
    parsed
}

/// Rows of a result file: one JSON object per line (or, in exports, one
/// JSON array).
fn read_rows(files: &CollectorFiles<'_>, name: &str, log: &mut CollectionLog) -> Option<Vec<Json>> {
    let text = files.read_text(files.find(name)?, log)?;
    if let Ok(Json::Array(rows)) = json::parse(&text) {
        return Some(rows);
    }
    let mut rows = Vec::new();
    let mut bad = 0u64;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        match json::parse(line) {
            Ok(row) => rows.push(row),
            Err(_) => bad += 1,
        }
    }
    if bad > 0 {
        log.gaps.push(format!("{name}: {bad} unreadable lines"));
    }
    Some(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_time_units_are_recognised() {
        let expected = Ts::from_unix_seconds(1_602_103_388).to_iso8601();
        assert_eq!(epoch_time(1_602_103_388_000_000_000).to_iso8601(), expected);
        assert_eq!(epoch_time(1_602_103_388_000_000).to_iso8601(), expected);
        assert_eq!(epoch_time(1_602_103_388).to_iso8601(), expected);
    }

    #[test]
    fn enums_as_numbers_or_names() {
        let names = [("FINISHED", STATE_FINISHED)];
        assert_eq!(enum_value(Some(&Json::Int(2)), &names), Some(2));
        assert_eq!(enum_value(Some(&Json::from("finished")), &names), Some(2));
        assert_eq!(enum_value(Some(&Json::from("OTHER")), &names), None);
        assert_eq!(enum_value(None, &names), None);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        #[test]
        fn hostile_rows_never_panic(
            state in proptest::prelude::any::<i64>(), size in proptest::prelude::any::<i64>(),
            stored in proptest::prelude::any::<i64>(), time in proptest::prelude::any::<i64>(),
            kind in "(idx|)", name in "\\PC{0,20}",
        ) {
            let context = json::parse(&format!(
                r#"{{"state": {state}, "create_time": {time}, "request": {{"artifacts": ["{name:?}"]}},
                   "query_stats": [{{"status": {state}, "Artifact": 3}}], "artifacts_with_results": [1, "a/b"]}}"#
            ));
            let upload = json::parse(&format!(
                r#"{{"_Components": ["a", 1], "file_size": {size}, "uploaded_size": {stored}, "Type": "{kind}", "_ts": {time}, "level": "ERROR"}}"#
            ));
            let mut log = CollectionLog::new(LayoutKind::Velociraptor);
            if let Ok(context) = context {
                read_context(&context, &mut log);
            }
            if let Ok(row) = upload {
                read_uploads(std::slice::from_ref(&row), &mut log);
                read_log(std::slice::from_ref(&row), &mut log);
            }
        }
    }
}
