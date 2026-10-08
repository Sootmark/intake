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

/// A volume by drive, live (`None`) or in a shadow copy.
type Volume = (char, Option<usize>);

/// Give each detected file on a volume whose `$MFT` the collection holds
/// its modification time from that `$MFT` ([`Detected::ntfs_modified`]):
/// a shadow copy's files from that shadow copy's. Returns the drives whose
/// `$MFT` was read.
pub(crate) fn apply(
    source: &dyn Source,
    entries: &[SourceEntry],
    files: &mut [Detected],
) -> Vec<char> {
    let mft_files: Vec<(Volume, &SourceEntry)> = files
        .iter()
        .filter_map(|file| {
            let host = file.host_path.as_ref()?;
            let drive = host.drive()?;
            let is_mft = host
                .to_string()
                .eq_ignore_ascii_case(&format!("{drive}:\\$MFT"));
            let entry = entries.iter().find(|e| e.path == file.path)?;
            (is_mft && entry.size <= MAX_MFT_BYTES).then_some(((drive, host.shadow_copy()), entry))
        })
        .collect();
    let mut times: HashMap<(Option<usize>, String), Ts> = HashMap::new();
    let mut volumes = Vec::new();
    let mut drives = Vec::new();
    for ((drive, shadow_copy), entry) in mft_files {
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
                let path = format!("{drive}:\\{}", file.display_path());
                times.insert(key(shadow_copy, &path), modified);
            }
        }
        volumes.push((drive, shadow_copy));
        if !drives.contains(&drive) {
            drives.push(drive);
        }
    }
    for file in files.iter_mut() {
        let host = file.host_path.as_ref().filter(|h| {
            h.drive()
                .is_some_and(|d| volumes.contains(&(d, h.shadow_copy())))
        });
        if let Some(host) = host {
            file.ntfs_modified = times
                .get(&key(host.shadow_copy(), &host.to_string()))
                .copied();
        }
    }
    drives
}

/// A host path as looked up: `c:\windows\…`, case folded (NTFS names
/// compare without case on Windows), in its shadow copy.
fn key(shadow_copy: Option<usize>, path: &str) -> (Option<usize>, String) {
    (shadow_copy, path.to_lowercase())
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read};
    use std::path::Path;

    use model::adapter::Confidence;

    use super::*;
    use crate::path::HostPath;

    /// The oldest shadow copy's `$MFT`.
    const SHADOW_MFT: &str = "vss1/C/$MFT";

    /// An image whose only readable file is [`SHADOW_MFT`]: FIN-WKS-07's.
    struct ShadowMftOnly(Vec<u8>);

    impl Source for ShadowMftOnly {
        fn name(&self) -> &'static str {
            "image"
        }

        fn entries(&self) -> io::Result<Vec<SourceEntry>> {
            Ok(Vec::new())
        }

        fn with_reader(
            &self,
            entry: &SourceEntry,
            f: &mut dyn FnMut(&mut dyn Read) -> io::Result<()>,
        ) -> io::Result<()> {
            if entry.path == SHADOW_MFT {
                f(&mut self.0.as_slice())
            } else {
                Err(io::Error::other("unreadable"))
            }
        }
    }

    /// The file at `host` (`/`-separated, on `C:`), live or in a shadow
    /// copy, as listed and detected.
    fn detected(host: &str, shadow_copy: Option<usize>) -> (SourceEntry, Detected) {
        let live = HostPath::new(Some('C'), host.split('/').map(str::to_owned).collect());
        let (path, host_path) = match shadow_copy {
            Some(index) => (
                format!("vss{}/C/{host}", index + 1),
                live.in_shadow_copy(index),
            ),
            None => (format!("C/{host}"), live),
        };
        let entry = SourceEntry {
            path: path.clone(),
            size: 1,
            modified: None,
        };
        let file = Detected {
            path,
            host_path: Some(host_path),
            size: 1,
            parser: None,
            confidence: Confidence::No,
            unreadable: None,
            ntfs_modified: None,
        };
        (entry, file)
    }

    #[test]
    fn a_shadow_copys_mft_times_only_its_own_files() {
        let mft = common::deflate::zlib_decompress(
            &std::fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fin-wks-07.mft.zlib"),
            )
            .unwrap(),
            1 << 20,
        )
        .unwrap();
        let (entries, mut files): (Vec<_>, Vec<_>) = [
            ("$MFT", None),
            ("ProgramData/Intel/m64.exe", None),
            ("$MFT", Some(0)),
            ("ProgramData/Intel/m64.exe", Some(0)),
        ]
        .into_iter()
        .map(|(host, shadow_copy)| detected(host, shadow_copy))
        .unzip();
        let drives = apply(&ShadowMftOnly(mft), &entries, &mut files);
        assert_eq!(drives, ['C']);
        let modified: Vec<_> = files
            .iter()
            .map(|f| f.ntfs_modified.and_then(|t| t.to_iso8601()))
            .collect();
        assert_eq!(modified[1], None, "the live volume's $MFT wasn't read");
        assert_eq!(modified[3].as_deref(), Some("2019-03-18T04:12:00.0000000Z"));
    }
}
