//! Disk images as evidence sources: E01, VHDX and raw (whole or split).
//!
//! The image is opened as a disk, its partitions are read, and every NTFS,
//! FAT and exFAT volume's files (NTFS alternate data streams included)
//! become source entries, read straight from the image without extraction.
//!
//! Entry paths follow one rule so layout recognition works unchanged:
//! - a volume that already holds a KAPE layout (`C/Windows/…`, as in a KAPE
//!   VHDX) keeps its paths;
//! - the volume holding `Windows` is the system volume and gets `C/`;
//! - any other volume gets `vol<slot>/`: no drive letter is guessed.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek};
use std::path::Path;

use common::json::Json;
use disk::{identify, partitions, FatVolume, FileEntry, Filesystem, NtfsVolume, SplitImage};
use ewf::Ewf;
use vhdx::Vhdx;

use crate::source::{Source, SourceEntry};

const E01_SIGNATURE: &[u8; 8] = b"EVF\x09\x0d\x0a\xff\x00";
const VHDX_SIGNATURE: &[u8; 8] = b"vhdxfile";
/// Extensions of raw images (first segment of split images included).
const RAW_EXTENSIONS: [&str; 5] = ["dd", "raw", "img", "001", "000"];
/// Top-level names showing a volume already holds a KAPE layout.
const KAPE_MARKERS: [&str; 3] = ["Windows", "Users", "$MFT"];

/// A disk readable as a stream.
trait Disk: Read + Seek {}
impl<T: Read + Seek> Disk for T {}

/// The container format of a disk image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerFormat {
    /// Expert Witness Format (`.E01`).
    E01,
    /// Hyper-V virtual disk (`.vhdx`), e.g. KAPE's `--vhdx` output.
    Vhdx,
    /// Raw (`dd`) image, whole or split.
    Raw,
    /// AD1 logical image (FTK Imager's custom content image).
    Ad1,
}

impl ContainerFormat {
    /// Stable identifier used in JSON output.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::E01 => "e01",
            Self::Vhdx => "vhdx",
            Self::Raw => "raw",
            Self::Ad1 => "ad1",
        }
    }
}

/// What intake learned about a disk image before parsing anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    /// The image format.
    pub format: ContainerFormat,
    /// Size of the acquired media in bytes (of the files, for an AD1).
    pub media_size: u64,
    /// MD5 embedded at acquisition (E01), lowercase hex.
    pub stored_md5: Option<String>,
    /// SHA-1 embedded at acquisition (E01), lowercase hex.
    pub stored_sha1: Option<String>,
    /// Case metadata recorded at acquisition (E01): `(field, value)`.
    pub acquisition: Vec<(&'static str, String)>,
    /// Whether entries are laid out as disk volumes (`C/…`, `vol<n>/…`)
    /// rather than as a collection found inside the image.
    pub volume_layout: bool,
    /// Conditions the analyst should know about.
    pub warnings: Vec<String>,
}

impl Container {
    /// The container as JSON.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("format", Json::from(self.format.id())),
            ("media_size", Json::from(self.media_size)),
            ("stored_md5", Json::from(self.stored_md5.clone())),
            ("stored_sha1", Json::from(self.stored_sha1.clone())),
            (
                "acquisition",
                Json::object(
                    self.acquisition
                        .iter()
                        .map(|(k, v)| (*k, Json::from(v.as_str()))),
                ),
            ),
            ("warnings", Json::from(self.warnings.clone())),
        ])
    }
}

/// Whether `path` looks like a disk image this module can open.
pub(crate) fn is_image(path: &Path, head: &[u8]) -> bool {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    head.starts_with(E01_SIGNATURE)
        || head.starts_with(VHDX_SIGNATURE)
        || extension.is_some_and(|e| RAW_EXTENSIONS.contains(&e.as_str()))
}

/// A volume's file system.
enum FileSystem {
    Ntfs(NtfsVolume),
    Fat(FatVolume),
}

impl FileSystem {
    fn read(
        &self,
        disk: &mut Box<dyn Disk>,
        file: &FileEntry,
        consume: &mut dyn FnMut(&mut dyn Read) -> io::Result<()>,
    ) -> io::Result<()> {
        match self {
            Self::Ntfs(ntfs) => ntfs.read(disk, file, consume),
            Self::Fat(fat) => fat.read(disk, file, consume),
        }
    }
}

struct Volume {
    file_system: FileSystem,
    files: Vec<FileEntry>,
    prefix: String,
}

/// A disk image seen as a source of files.
pub(crate) struct ImageSource {
    disk: RefCell<Box<dyn Disk>>,
    volumes: Vec<Volume>,
    index: HashMap<String, (usize, usize)>,
    container: Container,
    name: String,
}

impl ImageSource {
    pub(crate) fn open(path: &Path, head: &[u8], name: String) -> io::Result<Self> {
        let (mut disk, mut container) = open_container(path, head)?;
        let (_, parts) = partitions(&mut disk, container.media_size)?;
        let mut volumes = Vec::new();
        for part in &parts {
            let opened = match identify(&mut disk, part)? {
                Filesystem::Ntfs => Some(
                    NtfsVolume::open(&mut disk, part.offset, part.length).and_then(|ntfs| {
                        let files = ntfs.files(&mut disk)?;
                        Ok((FileSystem::Ntfs(ntfs), files))
                    }),
                ),
                Filesystem::Fat | Filesystem::ExFat => Some(
                    FatVolume::open(&mut disk, part.offset, part.length).map(|fat| {
                        let files = fat.files();
                        (FileSystem::Fat(fat), files)
                    }),
                ),
                Filesystem::Unknown => None,
            };
            match opened {
                Some(Ok((file_system, files))) => {
                    let prefix = volume_prefix(&files, part.slot);
                    volumes.push(Volume {
                        file_system,
                        files,
                        prefix,
                    });
                }
                Some(Err(error)) => container.warnings.push(format!(
                    "volume in partition {} unreadable: {error}",
                    part.slot
                )),
                None => {}
            }
        }
        if volumes.is_empty() {
            container
                .warnings
                .push("no readable NTFS, FAT or exFAT volume in the image".to_owned());
        }
        container.volume_layout = volumes.iter().any(|v| !v.prefix.is_empty());
        let mut index = HashMap::new();
        for (v, volume) in volumes.iter().enumerate() {
            for (f, file) in volume.files.iter().enumerate() {
                index.insert(entry_path(&volume.prefix, file), (v, f));
            }
        }
        Ok(Self {
            disk: RefCell::new(disk),
            volumes,
            index,
            container,
            name,
        })
    }
}

fn open_container(path: &Path, head: &[u8]) -> io::Result<(Box<dyn Disk>, Container)> {
    let container = |format, media_size| Container {
        format,
        media_size,
        stored_md5: None,
        stored_sha1: None,
        acquisition: Vec::new(),
        volume_layout: false,
        warnings: Vec::new(),
    };
    if head.starts_with(E01_SIGNATURE) {
        let image = Ewf::open_path(path)?;
        let mut info = container(ContainerFormat::E01, image.media_size());
        info.stored_md5.clone_from(&image.stored_hashes().md5);
        info.stored_sha1.clone_from(&image.stored_hashes().sha1);
        if let Some(a) = image.acquisition() {
            let fields = [
                ("case_number", &a.case_number),
                ("evidence_number", &a.evidence_number),
                ("description", &a.description),
                ("examiner", &a.examiner),
                ("notes", &a.notes),
                ("acquired", &a.acquired),
                ("software_version", &a.software_version),
            ];
            info.acquisition = fields
                .into_iter()
                .filter_map(|(k, v)| v.clone().map(|v| (k, v)))
                .collect();
        }
        return Ok((Box::new(image), info));
    }
    if head.starts_with(VHDX_SIGNATURE) {
        let image = Vhdx::open(BufReader::new(File::open(path)?))?;
        let mut info = container(ContainerFormat::Vhdx, image.virtual_size());
        if image.has_pending_log() {
            info.warnings.push(
                "VHDX was not closed cleanly: its log holds writes not applied to the blocks"
                    .to_owned(),
            );
        }
        return Ok((Box::new(image), info));
    }
    let image = SplitImage::open(path)?;
    let size = image.len();
    Ok((Box::new(image), container(ContainerFormat::Raw, size)))
}

/// See the module documentation for the rule.
fn volume_prefix(files: &[FileEntry], slot: usize) -> String {
    let holds_kape_layout = files.iter().any(|f| {
        matches!(f.path.as_slice(), [drive, top, ..] if drive.len() == 1 && drive.chars().all(|c| c.is_ascii_alphabetic()) && KAPE_MARKERS.contains(&top.as_str()))
    });
    let is_system_volume = files.iter().any(|f| {
        f.path
            .first()
            .is_some_and(|top| top.eq_ignore_ascii_case("Windows"))
    });
    if holds_kape_layout {
        String::new()
    } else if is_system_volume {
        "C".to_owned()
    } else {
        format!("vol{slot}")
    }
}

/// `prefix/a/b/file`, with `:stream` for alternate data streams. NTFS names
/// can't contain `/`, so the path splits back unambiguously.
fn entry_path(prefix: &str, file: &FileEntry) -> String {
    let mut path = String::from(prefix);
    for component in &file.path {
        if !path.is_empty() {
            path.push('/');
        }
        path.push_str(component);
    }
    if let Some(stream) = &file.stream {
        path.push(':');
        path.push_str(stream);
    }
    path
}

impl Source for ImageSource {
    fn name(&self) -> &str {
        &self.name
    }

    fn entries(&self) -> io::Result<Vec<SourceEntry>> {
        let mut entries: Vec<SourceEntry> = self
            .volumes
            .iter()
            .flat_map(|volume| {
                volume.files.iter().map(|file| SourceEntry {
                    path: entry_path(&volume.prefix, file),
                    size: file.size,
                    modified: file.times.modified,
                })
            })
            .collect();
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    fn with_reader(
        &self,
        entry: &SourceEntry,
        f: &mut dyn FnMut(&mut dyn Read) -> io::Result<()>,
    ) -> io::Result<()> {
        let &(v, file) = self
            .index
            .get(&entry.path)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such file in the image"))?;
        let volume = &self.volumes[v];
        let mut disk = self.disk.borrow_mut();
        volume.file_system.read(&mut disk, &volume.files[file], f)
    }

    fn container(&self) -> Option<&Container> {
        Some(&self.container)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str) -> FileEntry {
        FileEntry {
            path: path.split('/').map(str::to_owned).collect(),
            record: 0,
            stream: None,
            size: 0,
            times: disk::Times::default(),
        }
    }

    #[test]
    fn the_windows_volume_is_c() {
        let files = [file("$MFT"), file("Windows/System32/config/SYSTEM")];
        assert_eq!(volume_prefix(&files, 3), "C");
    }

    #[test]
    fn other_volumes_get_no_letter() {
        let files = [file("$MFT"), file("Shares/report.docx")];
        assert_eq!(volume_prefix(&files, 2), "vol2");
    }

    #[test]
    fn a_kape_vhdx_volume_keeps_its_layout() {
        let files = [
            file("C/Windows/System32/winevt/Logs/Security.evtx"),
            file("$MFT"),
        ];
        assert_eq!(volume_prefix(&files, 0), "");
    }

    #[test]
    fn streams_follow_the_path() {
        let mut entry = file("Users/a/tools.zip");
        entry.stream = Some("Zone.Identifier".to_owned());
        assert_eq!(
            entry_path("C", &entry),
            "C/Users/a/tools.zip:Zone.Identifier"
        );
        assert_eq!(entry_path("", &file("C/x")), "C/x");
    }

    #[test]
    fn recognises_images() {
        assert!(is_image(Path::new("x.bin"), E01_SIGNATURE));
        assert!(is_image(Path::new("x"), b"vhdxfile"));
        assert!(is_image(Path::new("disk.DD"), b"\0"));
        assert!(!is_image(Path::new("Security.evtx"), b"ElfFile\0"));
    }
}
