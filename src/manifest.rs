//! The evidence manifest: every file with its SHA-256, where chain of
//! custody starts.

use std::io;

use common::json::Json;
use common::sha256::hex;

use crate::layout::Layout;
use crate::path::HostPath;
use crate::source::{Source, SourceEntry};

/// One hashed evidence file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Path inside the source.
    pub path: String,
    /// Path on the host, when known.
    pub host_path: Option<HostPath>,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256, lowercase hex.
    pub sha256: String,
}

impl ManifestEntry {
    /// The entry as JSON.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("path", Json::from(self.path.as_str())),
            (
                "host_path",
                Json::from(self.host_path.as_ref().map(ToString::to_string)),
            ),
            ("size", Json::from(self.size)),
            ("sha256", Json::from(self.sha256.as_str())),
        ])
    }
}

/// Hash every entry of `source`.
///
/// # Errors
/// When an entry can't be read or fails its integrity check.
pub fn manifest(
    source: &dyn Source,
    layout: &Layout,
    entries: &[SourceEntry],
) -> io::Result<Vec<ManifestEntry>> {
    entries
        .iter()
        .map(|entry| {
            Ok(ManifestEntry {
                path: entry.path.clone(),
                host_path: layout.host_path(&entry.path),
                size: entry.size,
                sha256: hex(&source.sha256(entry)?),
            })
        })
        .collect()
}
