//! Collection layouts: how collectors store host files, and how to map them
//! back to the paths they had on the host.

use common::json::{self, Json};

use crate::path::HostPath;
use crate::source::{Source, SourceEntry};

/// The collector that produced a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutKind {
    /// KAPE target output: one directory per drive letter (`C/Windows/…`).
    Kape,
    /// A Velociraptor offline collection: files under `uploads/<accessor>/`
    /// with URL-encoded path components, plus collection metadata.
    Velociraptor,
    /// The volumes of a disk image: the system volume as `C/…`, others as
    /// `vol<slot>/…` with no drive letter (letters aren't stored on disk).
    DiskImage,
    /// Fox-IT's acquire: Windows volumes under `fs/<letter>:/…` (older
    /// versions: the system volume as `sysvol/…`).
    Acquire,
    /// UAC (Unix-like Artifacts Collector): host files under `[root]/…`,
    /// command output under `live_response/`, the run in `uac.log`.
    Uac,
    /// Anything else: loose files with no host paths.
    Loose,
}

impl core::fmt::Display for LayoutKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Kape => "KAPE",
            Self::Velociraptor => "Velociraptor",
            Self::DiskImage => "disk image",
            Self::Acquire => "acquire",
            Self::Uac => "UAC",
            Self::Loose => "loose files",
        })
    }
}

/// Where a host-name hint came from, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HintSource {
    /// Velociraptor's `client_info.json`.
    CollectorMetadata,
    /// The name of the folder the collection was wrapped in.
    FolderName,
}

impl core::fmt::Display for HintSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::CollectorMetadata => "collector metadata",
            Self::FolderName => "folder name",
        })
    }
}

/// A proposed host name. Proposals only: the analyst confirms identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHint {
    /// The proposed name.
    pub name: String,
    /// Where it came from.
    pub source: HintSource,
}

/// A recognised layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// The collector.
    pub kind: LayoutKind,
    /// A single wrapping folder all entries live under (`HOST01/` in
    /// `HOST01/C/Windows/…`), stripped before mapping paths.
    pub root: Option<String>,
    /// Proposed host name.
    pub host_hint: Option<HostHint>,
}

/// Top-level folders that show a drive letter directory really is a volume.
const VOLUME_MARKERS: [&str; 6] = [
    "Windows",
    "Users",
    "ProgramData",
    "$MFT",
    "$Extend",
    "$LogFile",
];
/// Files Velociraptor writes next to `uploads/`.
const VELOCIRAPTOR_METADATA: [&str; 4] = [
    "client_info.json",
    "collection_context.json",
    "uploads.json",
    "log.json",
];
const VELOCIRAPTOR_CLIENT_INFO: &str = "client_info.json";
/// Where UAC keeps the host's own name.
const UAC_HOSTNAME: &str = "live_response/system/hostname.txt";
/// Top-level folders that belong to a layout, never a wrapping folder.
const LAYOUT_FOLDERS: [&str; 5] = ["uploads", "fs", "sysvol", "[root]", "live_response"];
/// Top-level folders of a Unix file system: a loose `var/log/…` tree is a
/// file system's own, never wrapped in a folder named after the host.
const UNIX_ROOT_FOLDERS: [&str; 9] = [
    "var", "etc", "home", "root", "usr", "opt", "tmp", "private", "Library",
];
/// Upper bound on metadata read for hints.
const METADATA_LIMIT: usize = 1 << 20;

/// Recognise the layout of `source`, whose entries are `entries`.
#[must_use]
pub fn recognise(source: &dyn Source, entries: &[SourceEntry]) -> Layout {
    if source.container().is_some_and(|c| c.volume_layout) {
        return Layout {
            kind: LayoutKind::DiskImage,
            root: None,
            host_hint: None,
        };
    }
    let root = common_root(entries);
    let relative = |entry: &SourceEntry| strip_root(&entry.path, root.as_deref()).to_owned();
    let paths: Vec<String> = entries.iter().map(relative).collect();
    let folder_hint = root.as_ref().map(|name| HostHint {
        name: name.clone(),
        source: HintSource::FolderName,
    });

    if is_velociraptor(&paths) {
        let metadata_hint = entries
            .iter()
            .find(|e| relative(e) == VELOCIRAPTOR_CLIENT_INFO)
            .and_then(|e| velociraptor_hostname(source, e))
            .map(|name| HostHint {
                name,
                source: HintSource::CollectorMetadata,
            });
        return Layout {
            kind: LayoutKind::Velociraptor,
            root,
            host_hint: metadata_hint.or(folder_hint),
        };
    }
    if is_uac(&paths) {
        let hostname = entries
            .iter()
            .find(|e| relative(e) == UAC_HOSTNAME)
            .and_then(|e| source.head(e, 256).ok())
            .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_owned())
            .filter(|name| !name.is_empty() && !name.contains(char::is_whitespace))
            .map(|name| HostHint {
                name,
                source: HintSource::CollectorMetadata,
            });
        return Layout {
            kind: LayoutKind::Uac,
            root,
            host_hint: hostname.or(folder_hint),
        };
    }
    let kind = if is_acquire(&paths) {
        LayoutKind::Acquire
    } else if is_kape(&paths) {
        LayoutKind::Kape
    } else {
        LayoutKind::Loose
    };
    Layout {
        kind,
        root,
        host_hint: folder_hint,
    }
}

impl Layout {
    /// The host path of the entry stored at `path`, if the layout has one.
    #[must_use]
    pub fn host_path(&self, path: &str) -> Option<HostPath> {
        let path = strip_root(path, self.root.as_deref());
        match self.kind {
            LayoutKind::Kape => kape_host_path(path),
            LayoutKind::Velociraptor => velociraptor_host_path(path),
            LayoutKind::DiskImage => disk_image_host_path(path),
            LayoutKind::Acquire => acquire_host_path(path),
            LayoutKind::Uac => uac_host_path(path),
            LayoutKind::Loose => None,
        }
    }
}

/// A single top-level folder every entry lives under, unless that folder is
/// itself part of a layout (a drive letter or `uploads`).
fn common_root(entries: &[SourceEntry]) -> Option<String> {
    let first = entries.first()?.path.split_once('/')?.0;
    let shared = entries
        .iter()
        .all(|e| e.path.split_once('/').is_some_and(|(top, _)| top == first));
    let is_layout_folder = is_drive_folder(first)
        || LAYOUT_FOLDERS.contains(&first)
        || VOLUME_MARKERS.contains(&first)
        || UNIX_ROOT_FOLDERS.contains(&first);
    (shared && !is_layout_folder).then(|| first.to_owned())
}

fn strip_root<'p>(path: &'p str, root: Option<&str>) -> &'p str {
    root.and_then(|root| path.strip_prefix(root))
        .and_then(|rest| rest.strip_prefix('/'))
        .unwrap_or(path)
}

fn is_drive_folder(name: &str) -> bool {
    name.len() == 1 && name.chars().all(|c| c.is_ascii_alphabetic())
}

fn is_kape(paths: &[String]) -> bool {
    paths.iter().any(|path| {
        let mut parts = path.split('/');
        matches!((parts.next(), parts.next()), (Some(drive), Some(top)) if is_drive_folder(drive) && VOLUME_MARKERS.contains(&top))
    })
}

fn kape_host_path(path: &str) -> Option<HostPath> {
    let (drive, rest) = path.split_once('/')?;
    let letter = drive.chars().next().filter(|_| is_drive_folder(drive))?;
    Some(HostPath::new(
        Some(letter),
        rest.split('/').map(str::to_owned).collect(),
    ))
}

/// `C/…` → `C:\…`; `vol<slot>/…` → `\…` on an unknown drive.
fn disk_image_host_path(path: &str) -> Option<HostPath> {
    let (volume, rest) = path.split_once('/')?;
    let drive = volume.chars().next().filter(|_| is_drive_folder(volume));
    Some(HostPath::new(
        drive,
        rest.split('/').map(str::to_owned).collect(),
    ))
}

/// acquire: `fs/<letter>:/` (or `fs/<letter>/`) holding a Windows volume,
/// or the older `sysvol/`.
fn is_acquire(paths: &[String]) -> bool {
    paths.iter().any(|path| {
        let mut parts = path.split('/');
        match (parts.next(), parts.next(), parts.next()) {
            (Some("fs"), Some(volume), Some(top)) => {
                acquire_drive(volume).is_some() && VOLUME_MARKERS.contains(&top)
            }
            (Some("sysvol"), Some(top), _) => VOLUME_MARKERS.contains(&top),
            _ => false,
        }
    })
}

/// The drive letter of an acquire volume folder: `C:` or `c`.
fn acquire_drive(volume: &str) -> Option<char> {
    let letter = volume.strip_suffix(':').unwrap_or(volume);
    is_drive_folder(letter)
        .then(|| letter.chars().next())
        .flatten()
}

/// `fs/C:/…` → `C:\…`; `sysvol/…` → the system volume, `C:\…`.
fn acquire_host_path(path: &str) -> Option<HostPath> {
    let components = |rest: &str| rest.split('/').map(str::to_owned).collect();
    if let Some(rest) = path.strip_prefix("sysvol/") {
        return Some(HostPath::new(Some('C'), components(rest)));
    }
    let (volume, rest) = path.strip_prefix("fs/")?.split_once('/')?;
    Some(HostPath::new(
        Some(acquire_drive(volume)?),
        components(rest),
    ))
}

/// UAC: host files under `[root]/` and its own `uac.log` or `live_response/`.
fn is_uac(paths: &[String]) -> bool {
    paths.iter().any(|p| p.starts_with("[root]/"))
        && paths
            .iter()
            .any(|p| p == "uac.log" || p.starts_with("live_response/"))
}

/// `[root]/etc/passwd` → `/etc/passwd`.
fn uac_host_path(path: &str) -> Option<HostPath> {
    let rest = path.strip_prefix("[root]/")?;
    Some(HostPath::unix(rest.split('/').map(str::to_owned).collect()))
}

fn is_velociraptor(paths: &[String]) -> bool {
    let has_uploads = paths.iter().any(|p| p.starts_with("uploads/"));
    let has_metadata = paths
        .iter()
        .any(|p| VELOCIRAPTOR_METADATA.contains(&p.as_str()));
    has_uploads && has_metadata
}

/// `uploads/<accessor>/<url-encoded components…>` → host path.
fn velociraptor_host_path(path: &str) -> Option<HostPath> {
    let mut parts = path.split('/');
    if parts.next() != Some("uploads") {
        return None;
    }
    parts.next()?; // accessor: auto, ntfs, file, …
    let decoded: Vec<String> = parts.map(percent_decode).collect();
    (!decoded.is_empty()).then(|| HostPath::parse_windows(&decoded.join("\\")))
}

/// Decode `%XX` escapes. Invalid escapes are kept as they are.
fn percent_decode(component: &str) -> String {
    let bytes = component.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if let Some(byte) = escape_at(component, i) {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The byte encoded by a valid `%XX` escape starting at `i`, if there is one.
fn escape_at(component: &str, i: usize) -> Option<u8> {
    let hex = component.get(i..i + 3)?.strip_prefix('%')?;
    u8::from_str_radix(hex, 16).ok()
}

fn velociraptor_hostname(source: &dyn Source, entry: &SourceEntry) -> Option<String> {
    let bytes = source.head(entry, METADATA_LIMIT).ok()?;
    let info = json::parse(std::str::from_utf8(&bytes).ok()?).ok()?;
    ["Hostname", "Fqdn"]
        .iter()
        .find_map(|key| info.get(key).and_then(Json::as_str))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

impl LayoutKind {
    /// Stable identifier used in JSON output.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Kape => "kape",
            Self::Velociraptor => "velociraptor",
            Self::DiskImage => "disk_image",
            Self::Acquire => "acquire",
            Self::Uac => "uac",
            Self::Loose => "loose",
        }
    }
}

impl HintSource {
    /// Stable identifier used in JSON output.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::CollectorMetadata => "collector_metadata",
            Self::FolderName => "folder_name",
        }
    }
}

impl Layout {
    /// The layout as JSON.
    #[must_use]
    pub fn to_json(&self) -> Json {
        let hint = self.host_hint.as_ref().map(|hint| {
            Json::object([
                ("name", Json::from(hint.name.as_str())),
                ("source", Json::from(hint.source.id())),
            ])
        });
        Json::object([
            ("kind", Json::from(self.kind.id())),
            ("root", Json::from(self.root.clone())),
            ("host_hint", hint.unwrap_or(Json::Null)),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_velociraptor_paths() {
        let path =
            velociraptor_host_path("uploads/auto/C%3A/Windows/System32/winevt/Logs/Security.evtx")
                .unwrap();
        assert_eq!(
            path.to_string(),
            r"C:\Windows\System32\winevt\Logs\Security.evtx"
        );
        let raw_device = velociraptor_host_path("uploads/ntfs/%5C%5C.%5CC%3A/$MFT").unwrap();
        assert_eq!(raw_device.to_string(), r"C:\$MFT");
        assert_eq!(
            velociraptor_host_path("results/Windows.System.Pslist.json"),
            None
        );
    }

    #[test]
    fn file_system_folders_are_not_hosts() {
        let entries = |paths: &[&str]| -> Vec<SourceEntry> {
            paths
                .iter()
                .map(|path| SourceEntry {
                    path: (*path).to_owned(),
                    size: 1,
                    modified: None,
                })
                .collect()
        };
        assert_eq!(
            common_root(&entries(&["web1/var/log/auth.log", "web1/var/log/syslog"])),
            Some("web1".to_owned())
        );
        assert_eq!(
            common_root(&entries(&["var/log/auth.log", "var/log/syslog"])),
            None
        );
        assert_eq!(
            common_root(&entries(&["Windows/System32/config/SYSTEM"])),
            None
        );
    }

    #[test]
    fn keeps_invalid_escapes() {
        assert_eq!(percent_decode("100%25"), "100%");
        assert_eq!(percent_decode("50%"), "50%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn maps_kape_paths() {
        let path = kape_host_path("C/Windows/System32/config/SYSTEM").unwrap();
        assert_eq!(path.to_string(), r"C:\Windows\System32\config\SYSTEM");
        assert_eq!(kape_host_path("ConsoleLog.txt"), None);
    }

    #[test]
    fn maps_disk_image_paths() {
        let system = disk_image_host_path("C/Windows/System32/config/SAM").unwrap();
        assert_eq!(system.to_string(), r"C:\Windows\System32\config\SAM");
        let data = disk_image_host_path("vol2/Shares/report.docx:Zone.Identifier").unwrap();
        assert_eq!(data.drive(), None);
        assert_eq!(data.to_string(), r"\Shares\report.docx:Zone.Identifier");
    }
}
