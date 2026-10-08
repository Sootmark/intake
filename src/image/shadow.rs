//! Volume Shadow Copies of a disk image's NTFS volumes.
//!
//! Each snapshot's view of its volume is read as a volume of its own, its
//! files under `vss<n>/` followed by the live volume's own path: the oldest
//! snapshot (the catalog's index 0) is `vss1`, as libvshadow's
//! `vshadowmount` and dfVFS name them, so the System hive of the system
//! volume as the oldest snapshot kept it is
//! `vss1/C/Windows/System32/config/SYSTEM`. The layout reads that back as
//! the live file's host path, `C:\Windows\System32\config\SYSTEM`, in
//! shadow copy 0 ([`HostPath::shadow_copy`](crate::HostPath::shadow_copy)):
//! parsers recognise the file as they do the live one, and the entry path
//! still says which snapshot it came from.

use std::cell::RefCell;

use common::json::Json;
use common::time::Ts;
use disk::NtfsVolume;
use vss::Shadows;

use super::handle::DiskHandle;
use super::{Container, FileSystem, Volume};

/// The prefix of shadow copy entry paths, before the copy's number.
const PREFIX: &str = "vss";

/// A shadow copy found on a volume of the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowCopy {
    /// The live volume's entry path prefix (`C`, `vol<slot>`).
    pub volume: String,
    /// Its index in the volume's catalog: 0 for the oldest.
    pub index: usize,
    /// When it was taken (UTC).
    pub created: Ts,
    /// Its store's GUID, which names its file in `System Volume
    /// Information`.
    pub store_id: String,
    /// How many entries its files gave; `None` when it wasn't read (see the
    /// container's warnings).
    pub entries: Option<u64>,
}

impl ShadowCopy {
    /// The prefix of its files' entry paths: `vss1/C` for the system
    /// volume's oldest.
    #[must_use]
    pub fn path(&self) -> String {
        format!("{}/{}", name(self.index), self.volume)
    }

    /// The shadow copy as JSON.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("volume", Json::from(self.volume.as_str())),
            ("index", Json::from(self.index as u64)),
            ("path", Json::from(self.path())),
            ("created", Json::from(self.created.to_iso8601())),
            ("store_id", Json::from(self.store_id.as_str())),
            ("entries", Json::from(self.entries)),
        ])
    }
}

/// `vss<index + 1>`.
fn name(index: usize) -> String {
    format!("{PREFIX}{}", index + 1)
}

/// The index of the shadow copy `name` names, when it is a name [`name`]
/// gives.
fn index_of(name: &str) -> Option<usize> {
    let number = name.strip_prefix(PREFIX)?;
    if number.starts_with('0') || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    number.parse::<usize>().ok()?.checked_sub(1)
}

/// The shadow copy index an entry path is in, and the path in the live
/// volume's layout: `vss1/C/x` is `(Some(0), "C/x")`, `C/x` is
/// `(None, "C/x")`.
pub(crate) fn split(path: &str) -> (Option<usize>, &str) {
    path.split_once('/')
        .and_then(|(top, rest)| Some((Some(index_of(top)?), rest)))
        .unwrap_or((None, path))
}

/// The shadow copies of the NTFS volume `volume` (a handle on it, at its
/// start), whose files are under `prefix`: the newest `limit` of them
/// (all for `None`) read as volumes of their own. Each one found is
/// recorded in `container`, and whatever couldn't be read is a warning
/// there, never an error.
pub(super) fn read(
    volume: &DiskHandle,
    prefix: &str,
    limit: Option<usize>,
    container: &mut Container,
) -> Vec<Volume> {
    let shadows = match vss::read_catalog(&mut volume.clone()) {
        Ok(shadows) => shadows,
        Err(error) => {
            container.warnings.push(format!(
                "shadow copies of volume {prefix} unreadable: {error}"
            ));
            return Vec::new();
        }
    };
    container.warnings.extend(
        shadows
            .problems
            .iter()
            .map(|problem| format!("shadow copies of volume {prefix}: {problem}")),
    );
    let total = shadows.snapshots.len();
    let first_read = limit.map_or(0, |limit| total.saturating_sub(limit));
    if first_read > 0 {
        container.warnings.push(format!(
            "{first_read} of the {total} shadow copies of volume {prefix} not read: \
             only the newest {} were asked for",
            total - first_read
        ));
    }
    let mut volumes = Vec::new();
    for snapshot in &shadows.snapshots {
        let mut found = ShadowCopy {
            volume: prefix.to_owned(),
            index: snapshot.index,
            created: snapshot.creation_time,
            store_id: snapshot.store_id.to_string(),
            entries: None,
        };
        if snapshot.index >= first_read {
            match open(&shadows, volume, &found, container) {
                Ok(view) => {
                    found.entries = Some(view.files.len() as u64);
                    volumes.push(view);
                }
                Err(error) => container
                    .warnings
                    .push(format!("shadow copy {} unreadable: {error}", found.path())),
            }
        }
        container.shadow_copies.push(found);
    }
    volumes
}

/// The volume as shadow copy `found` kept it, its view built once.
fn open(
    shadows: &Shadows,
    volume: &DiskHandle,
    found: &ShadowCopy,
    container: &mut Container,
) -> std::io::Result<Volume> {
    let mut view = shadows.snapshot_view(volume.clone(), found.index)?;
    container.warnings.extend(
        view.problems()
            .iter()
            .map(|problem| format!("shadow copy {}: {problem}", found.path())),
    );
    let length = view.len();
    let ntfs = NtfsVolume::open(&mut view, 0, length)?;
    let files = ntfs.files(&mut view)?;
    Ok(Volume {
        reader: RefCell::new(Box::new(view)),
        file_system: FileSystem::Ntfs(ntfs),
        files,
        prefix: found.path(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_split_into_their_shadow_copy() {
        assert_eq!(split("vss1/C/Windows"), (Some(0), "C/Windows"));
        assert_eq!(split("vss12/vol2/x"), (Some(11), "vol2/x"));
        assert_eq!(split("C/Windows"), (None, "C/Windows"));
        for live in [
            "vss0/C/x",
            "vss01/C/x",
            "vss/C/x",
            "vss1",
            "vssx/C",
            "vss+1/C",
        ] {
            assert_eq!(split(live), (None, live));
        }
    }

    #[test]
    fn the_oldest_is_vss1() {
        let found = ShadowCopy {
            volume: "C".to_owned(),
            index: 0,
            created: Ts::from_unix_seconds(0),
            store_id: String::new(),
            entries: None,
        };
        assert_eq!(found.path(), "vss1/C");
        assert_eq!(split(&format!("{}/x", found.path())), (Some(0), "C/x"));
    }
}
