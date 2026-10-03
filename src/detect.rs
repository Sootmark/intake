//! Deciding which parser handles each file.

use std::io;

use common::json::Json;
use common::time::Ts;
use model::adapter::{Adapter, Confidence};

use crate::layout::Layout;
use crate::path::HostPath;
use crate::source::{Source, SourceEntry};

/// Bytes read from the start of each file for adapters to probe.
pub const PROBE_SIZE: usize = 4096;

/// What detection concluded about one file.
#[derive(Debug, Clone, PartialEq)]
pub struct Detected {
    /// Path inside the source.
    pub path: String,
    /// Path the file had on the host, when the layout knows it.
    pub host_path: Option<HostPath>,
    /// Size in bytes.
    pub size: u64,
    /// The parser that will read it, if any adapter recognised it.
    pub parser: Option<&'static str>,
    /// How sure that adapter is.
    pub confidence: Confidence,
    /// Why the file couldn't be read (an encrypted NTFS stream, damage),
    /// when it couldn't: it's kept, not parsed.
    pub unreadable: Option<String>,
    /// Its modification time on the host (UTC), from the volume's `$MFT`
    /// when the collection holds it: the file's own time, rather than the
    /// copy's.
    pub ntfs_modified: Option<Ts>,
}

impl Detected {
    /// The file as JSON.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("path", Json::from(self.path.as_str())),
            (
                "host_path",
                Json::from(self.host_path.as_ref().map(ToString::to_string)),
            ),
            ("size", Json::from(self.size)),
            ("parser", Json::from(self.parser)),
            ("unreadable", Json::from(self.unreadable.clone())),
            (
                "ntfs_modified",
                Json::from(self.ntfs_modified.and_then(|t| t.to_iso8601())),
            ),
        ])
    }
}

/// Probe every entry with every adapter, keeping the most confident one.
/// An entry that can't be read is kept, with why, and goes to no parser.
///
/// # Errors
/// None today: kept for sources that may fail as a whole.
pub fn detect(
    source: &dyn Source,
    layout: &Layout,
    entries: &[SourceEntry],
    adapters: &[&dyn Adapter],
) -> io::Result<Vec<Detected>> {
    entries
        .iter()
        .map(|entry| {
            let host_path = layout.host_path(&entry.path);
            let head = match source.head(entry, PROBE_SIZE) {
                Ok(head) => head,
                Err(error) => {
                    return Ok(Detected {
                        path: entry.path.clone(),
                        host_path,
                        size: entry.size,
                        parser: None,
                        confidence: Confidence::No,
                        unreadable: Some(error.to_string()),
                        ntfs_modified: None,
                    })
                }
            };
            let name = host_path
                .as_ref()
                .and_then(HostPath::file_name)
                .unwrap_or(&entry.path);
            let best = adapters
                .iter()
                .map(|adapter| (adapter.probe(name, &head), adapter.parser().name))
                .filter(|(confidence, _)| *confidence > Confidence::No)
                .max_by_key(|(confidence, _)| *confidence);
            Ok(Detected {
                path: entry.path.clone(),
                host_path,
                size: entry.size,
                parser: best.map(|(_, parser)| parser),
                confidence: best.map_or(Confidence::No, |(confidence, _)| confidence),
                unreadable: None,
                ntfs_modified: None,
            })
        })
        .collect()
}
