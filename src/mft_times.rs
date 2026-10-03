//! File times from a collection's own `$MFT`. A triage collection copies
//! files with times of its own (the zip's, the copy's); the volume's
//! `$MFT`, when collected too, has each file's times on the host.

use std::collections::HashMap;

use common::time::Ts;
use disk::Mft;

use crate::detect::Detected;
use crate::source::{Source, SourceEntry};

/// Largest `$MFT` read for times: past this, the source's times stay.
const MAX_MFT_BYTES: u64 = 2 << 30;

/// Give each detected file on a drive whose `$MFT` the collection holds
/// its modification time from that `$MFT` ([`Detected::ntfs_modified`]).
/// Returns the drives whose `$MFT` was read.
pub(crate) fn apply(
    source: &dyn Source,
    entries: &[SourceEntry],
    files: &mut [Detected],
) -> Vec<char> {
    let mft_files: Vec<(char, &SourceEntry)> = files
        .iter()
        .filter_map(|file| {
            let host = file.host_path.as_ref()?;
            let drive = host.drive()?;
            let is_mft = host
                .to_string()
                .eq_ignore_ascii_case(&format!("{drive}:\\$MFT"));
            let entry = entries.iter().find(|e| e.path == file.path)?;
            (is_mft && entry.size <= MAX_MFT_BYTES).then_some((drive, entry))
        })
        .collect();
    let mut times: HashMap<String, Ts> = HashMap::new();
    let mut drives = Vec::new();
    for (drive, entry) in mft_files {
        let mut mft = None;
        if source
            .with_reader(entry, &mut |reader| {
                mft = Some(Mft::read(reader)?);
                Ok(())
            })
            .is_err()
        {
            continue;
        }
        let Some(mft) = mft else { continue };
        for file in mft.files.iter().filter(|f| f.in_use && !f.is_orphan()) {
            if let Some(modified) = file.times.modified {
                times.insert(key(drive, &file.display_path()), modified);
            }
        }
        drives.push(drive);
    }
    for file in files.iter_mut() {
        let host = file
            .host_path
            .as_ref()
            .filter(|h| h.drive().is_some_and(|d| drives.contains(&d)));
        if let Some(host) = host {
            file.ntfs_modified = times.get(&host.to_string().to_lowercase()).copied();
        }
    }
    drives
}

/// A host path as looked up: `c:\windows\…`, case folded (NTFS names
/// compare without case on Windows).
fn key(drive: char, path: &str) -> String {
    format!("{drive}:\\{path}").to_lowercase()
}
