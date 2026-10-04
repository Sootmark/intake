//! The Sootmark collector's archives: `outcome.json` (the run: version,
//! plan, host, start and counts) and `manifest.jsonl` (one line per file
//! with its SHA-256 and status, and one per rule that found nothing).

use common::json::{self, Json};
use common::time::Ts;

use super::{CollectionLog, CollectorFiles, Failure, Outcome, PartialFile, RecordedHash};
use crate::layout::LayoutKind;

/// The run's record.
pub(crate) const OUTCOME: &str = "outcome.json";
/// The files' record.
pub(crate) const MANIFEST: &str = "manifest.jsonl";
/// What `outcome.json` names the collector.
pub(crate) const COLLECTOR: &str = "sootmark-collector";

pub(super) fn read(files: &CollectorFiles<'_>) -> CollectionLog {
    let mut log = CollectionLog::new(LayoutKind::Sootmark);
    let text = |name: &str, log: &mut CollectionLog| {
        let found = files
            .find(name)
            .and_then(|entry| files.read_text(entry, log));
        if found.is_none() {
            log.gaps.push(format!("no readable {name}"));
        }
        found
    };
    let outcome = text(OUTCOME, &mut log).and_then(|text| json::parse(&text).ok());
    if let Some(outcome) = &outcome {
        let field = |name: &str| outcome.get(name).and_then(Json::as_str);
        log.version = field("version").map(str::to_owned);
        log.started = field("started").and_then(Ts::parse_iso8601_utc);
        // The collector writes outcome.json last, when the archive is
        // complete.
        log.outcome = Outcome::Completed;
    }
    let Some(manifest) = text(MANIFEST, &mut log) else {
        return log;
    };
    for (number, line) in manifest.lines().enumerate() {
        let Ok(line) = json::parse(line) else {
            log.gaps
                .push(format!("{MANIFEST} line {}: not JSON", number + 1));
            continue;
        };
        record(&mut log, &line);
    }
    if let Some(outcome) = &outcome {
        let count = |name: &str| outcome.get(name).and_then(Json::as_u64).unwrap_or(0);
        let stored = count("collected") + count("partial");
        if stored != log.files_recorded {
            log.gaps.push(format!(
                "{OUTCOME} counts {stored} files stored, {MANIFEST} lists {}",
                log.files_recorded
            ));
        }
    }
    log
}

/// One manifest line into `log`.
fn record(log: &mut CollectionLog, line: &Json) {
    let field = |name: &str| line.get(name).and_then(Json::as_str).unwrap_or_default();
    let number = |name: &str| line.get(name).and_then(Json::as_u64).unwrap_or(0);
    let rule = field("rule");
    if !rule.is_empty() && !log.requested.iter().any(|r| r == rule) {
        log.requested.push(rule.to_owned());
    }
    match field("status") {
        status @ ("ok" | "partial") => {
            log.files_recorded += 1;
            let stored = field("stored").to_owned();
            if status == "partial" {
                log.partial.push(PartialFile {
                    path: stored.clone(),
                    expected: number("size"),
                    stored: number("collected_bytes"),
                });
            }
            log.hashes.push(RecordedHash {
                path: stored,
                algorithm: "sha256",
                hex: field("sha256").to_owned(),
                size: number("collected_bytes"),
            });
        }
        "error" => log.failed.push(Failure {
            item: field("path").to_owned(),
            reason: field("why").to_owned(),
        }),
        "skipped_limit" => log.failed.push(Failure {
            item: field("path").to_owned(),
            reason: "not reached before the collector's deadline".to_owned(),
        }),
        "not_found" => log.without_results.push(rule.to_owned()),
        other => log
            .gaps
            .push(format!("{MANIFEST}: unknown status '{other}'")),
    }
}
