//! What the collector recorded about its own collection: what was asked
//! for, what failed, what came back empty, and what it logged.
//!
//! This feeds coverage (UX spec §5): an item that *failed to collect* is
//! "not collected", which is not the same as one that was collected and
//! found nothing ("absent"). Never infer either from missing files alone.

mod kape;
mod velociraptor;

use std::collections::HashMap;
use std::io::{self, Read};

use common::hex;
use common::json::Json;
use common::md5::Md5;
use common::sha1::Sha1;
use common::sha256::Sha256;
use common::time::Ts;

use crate::layout::{Layout, LayoutKind};
use crate::source::{Source, SourceEntry};

/// Upper bound on error lines kept; the rest are counted, not stored.
const MAX_LINES_KEPT: usize = 10_000;
/// Upper bound on each collector file read.
const READ_LIMIT: u64 = 64 << 20;

/// How the collection ended, as the collector reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Completed normally.
    Completed,
    /// Ended with an error: the collector's message.
    Failed(String),
    /// Still running, interrupted, or not recorded.
    Unknown,
}

/// Something that was asked for and not collected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// The artifact, target or file.
    pub item: String,
    /// Why, in the collector's words.
    pub reason: String,
}

/// A line the collector logged at warning or error level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// When it was logged, if recorded.
    pub time: Option<Ts>,
    /// The message, trimmed.
    pub message: String,
}

/// A file stored smaller than its size on the host (not a sparse file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialFile {
    /// Path inside the collection.
    pub path: String,
    /// Size on the host.
    pub expected: u64,
    /// Bytes stored.
    pub stored: u64,
}

/// A hash the collector recorded for a file it stored, to check the
/// stored copy against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedHash {
    /// Path inside the collection.
    pub path: String,
    /// `sha1`, `sha256` or `md5`.
    pub algorithm: &'static str,
    /// Lowercase hex digest.
    pub hex: String,
    /// Size recorded with it.
    pub size: u64,
}

/// The collector's own record of the collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionLog {
    /// Which collector wrote it.
    pub collector: LayoutKind,
    /// Collector version, when recorded.
    pub version: Option<String>,
    /// When the collection started.
    pub started: Option<Ts>,
    /// How it ended.
    pub outcome: Outcome,
    /// What was asked for (artifacts or targets).
    pub requested: Vec<String>,
    /// What was asked for and not collected: "not collected" in coverage.
    pub failed: Vec<Failure>,
    /// What was looked for and not there (artifacts without results, files
    /// gone by copy time): "absent" in coverage.
    pub without_results: Vec<String>,
    /// Error lines logged, up to 10,000 (the rest are only counted).
    pub errors: Vec<LogLine>,
    /// Error lines logged in total.
    pub error_count: u64,
    /// Warning lines logged in total.
    pub warning_count: u64,
    /// Files the collector recorded as collected.
    pub files_recorded: u64,
    /// Files stored incomplete.
    pub partial: Vec<PartialFile>,
    /// Hashes recorded for stored files (KAPE's CopyLog SHA-1s).
    pub hashes: Vec<RecordedHash>,
    /// Why this record may be incomplete or inconsistent: collector files
    /// missing or unreadable, totals that don't add up.
    pub gaps: Vec<String>,
}

impl CollectionLog {
    fn new(collector: LayoutKind) -> Self {
        Self {
            collector,
            version: None,
            started: None,
            outcome: Outcome::Unknown,
            requested: Vec::new(),
            failed: Vec::new(),
            without_results: Vec::new(),
            errors: Vec::new(),
            error_count: 0,
            warning_count: 0,
            files_recorded: 0,
            partial: Vec::new(),
            hashes: Vec::new(),
            gaps: Vec::new(),
        }
    }

    fn log_error(&mut self, line: LogLine) {
        self.error_count += 1;
        if self.errors.len() < MAX_LINES_KEPT {
            self.errors.push(line);
        }
    }

    /// The record as JSON.
    #[must_use]
    pub fn to_json(&self) -> Json {
        let outcome = match &self.outcome {
            Outcome::Completed => Json::from("completed"),
            Outcome::Failed(message) => Json::object([("failed", Json::from(message.as_str()))]),
            Outcome::Unknown => Json::Null,
        };
        let strings =
            |items: &[String]| Json::Array(items.iter().map(|s| Json::from(s.as_str())).collect());
        Json::object([
            ("collector", Json::from(self.collector.id())),
            ("version", Json::from(self.version.clone())),
            (
                "started",
                Json::from(self.started.as_ref().and_then(Ts::to_iso8601)),
            ),
            ("outcome", outcome),
            ("requested", strings(&self.requested)),
            (
                "failed",
                Json::Array(
                    self.failed
                        .iter()
                        .map(|f| {
                            Json::object([
                                ("item", Json::from(f.item.as_str())),
                                ("reason", Json::from(f.reason.as_str())),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("without_results", strings(&self.without_results)),
            ("error_count", Json::from(self.error_count)),
            ("warning_count", Json::from(self.warning_count)),
            (
                "errors",
                Json::Array(
                    self.errors
                        .iter()
                        .map(|line| {
                            Json::object([
                                (
                                    "time",
                                    Json::from(line.time.as_ref().and_then(Ts::to_iso8601)),
                                ),
                                ("message", Json::from(line.message.as_str())),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("files_recorded", Json::from(self.files_recorded)),
            (
                "partial",
                Json::Array(
                    self.partial
                        .iter()
                        .map(|p| {
                            Json::object([
                                ("path", Json::from(p.path.as_str())),
                                ("expected", Json::from(p.expected)),
                                ("stored", Json::from(p.stored)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("recorded_hashes", Json::from(self.hashes.len() as u64)),
            ("gaps", strings(&self.gaps)),
        ])
    }
}

/// A stored file whose content doesn't match the hash the collector
/// recorded when it copied it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashMismatch {
    /// Path inside the collection.
    pub path: String,
    /// What the collector recorded.
    pub recorded: String,
    /// What the stored copy hashes to now.
    pub computed: String,
}

/// The result of checking stored files against the collector's hashes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HashCheck {
    /// Files hashed and compared.
    pub checked: u64,
    /// Files whose content changed since collection.
    pub mismatched: Vec<HashMismatch>,
    /// Files the collector recorded but the source doesn't hold.
    pub missing: Vec<String>,
}

impl HashCheck {
    /// Whether every recorded file is present and unchanged.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.mismatched.is_empty() && self.missing.is_empty()
    }
}

/// Hash every stored file the collector recorded a hash for, and compare.
/// Reads each of those files in full.
///
/// # Errors
/// When a file can't be read.
pub fn check_hashes(
    source: &dyn Source,
    layout: &Layout,
    log: &CollectionLog,
) -> io::Result<HashCheck> {
    let entries = source.entries()?;
    let files = CollectorFiles {
        source,
        root: layout.root.as_deref(),
        entries: &entries,
    };
    let by_path: HashMap<&str, &SourceEntry> = entries
        .iter()
        .map(|e| (files.relative(&e.path), e))
        .collect();
    let mut check = HashCheck::default();
    for recorded in &log.hashes {
        let Some(entry) = by_path.get(recorded.path.as_str()) else {
            check.missing.push(recorded.path.clone());
            continue;
        };
        let computed = digest(source, entry, recorded.algorithm)?;
        check.checked += 1;
        if computed != recorded.hex {
            check.mismatched.push(HashMismatch {
                path: recorded.path.clone(),
                recorded: recorded.hex.clone(),
                computed,
            });
        }
    }
    Ok(check)
}

fn digest(source: &dyn Source, entry: &SourceEntry, algorithm: &str) -> io::Result<String> {
    fn stream<H: io::Write>(
        source: &dyn Source,
        entry: &SourceEntry,
        hasher: &mut H,
    ) -> io::Result<()> {
        source.with_reader(entry, &mut |reader| io::copy(reader, hasher).map(|_| ()))
    }
    Ok(match algorithm {
        "sha1" => {
            let mut hasher = Sha1::new();
            stream(source, entry, &mut hasher)?;
            hex::encode(&hasher.finalize())
        }
        "md5" => {
            let mut hasher = Md5::new();
            stream(source, entry, &mut hasher)?;
            hex::encode(&hasher.finalize())
        }
        _ => {
            let mut hasher = Sha256::new();
            stream(source, entry, &mut hasher)?;
            hex::encode(&hasher.finalize())
        }
    })
}

/// Read the collector's record of the collection in `source`, if its
/// layout has one.
#[must_use]
pub fn read(
    source: &dyn Source,
    layout: &Layout,
    entries: &[SourceEntry],
) -> Option<CollectionLog> {
    let files = CollectorFiles {
        source,
        root: layout.root.as_deref(),
        entries,
    };
    match layout.kind {
        LayoutKind::Velociraptor => Some(velociraptor::read(&files)),
        LayoutKind::Kape => Some(kape::read(&files)),
        LayoutKind::DiskImage | LayoutKind::Acquire | LayoutKind::Uac | LayoutKind::Loose => None,
    }
}

/// The collector's files in a source, found relative to the layout root.
struct CollectorFiles<'s> {
    source: &'s dyn Source,
    root: Option<&'s str>,
    entries: &'s [SourceEntry],
}

impl CollectorFiles<'_> {
    /// The entry stored at `relative` (under the layout root).
    fn find(&self, relative: &str) -> Option<&SourceEntry> {
        self.entries
            .iter()
            .find(|e| self.relative(&e.path) == relative)
    }

    /// The content of `entry` as text, noting in `log` when it can't be
    /// read in full.
    fn read_text(&self, entry: &SourceEntry, log: &mut CollectionLog) -> Option<String> {
        let name = self.relative(&entry.path);
        let mut bytes = Vec::new();
        let read = self.source.with_reader(entry, &mut |reader| {
            reader.take(READ_LIMIT).read_to_end(&mut bytes).map(|_| ())
        });
        if let Err(error) = read {
            log.gaps.push(format!("{name}: unreadable ({error})"));
            return None;
        }
        if entry.size > READ_LIMIT {
            log.gaps.push(format!(
                "{name}: only the first {} MiB read",
                READ_LIMIT >> 20
            ));
        }
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// `path` without the layout root.
    fn relative<'p>(&self, path: &'p str) -> &'p str {
        self.root
            .and_then(|root| path.strip_prefix(root))
            .and_then(|rest| rest.strip_prefix('/'))
            .unwrap_or(path)
    }
}
