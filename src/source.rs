//! Evidence sources: a directory, a zip archive, or a single file.

use std::cell::RefCell;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek};
use std::path::{Path, PathBuf};

use common::sha256::Sha256;
use common::time::Ts;
use zip::Archive;

use crate::image::{self, Container, ImageSource};
use crate::logical;
use crate::protected::{self, Credentials, Locked, Scheme};
use crate::tar::{self, TarSource};

/// One file inside a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEntry {
    /// `/`-separated path inside the source.
    pub path: String,
    /// Size in bytes.
    pub size: u64,
    /// When the file was last modified, as the source records it (UTC
    /// mostly); `None` when it doesn't. Zip entries and FAT volumes keep a
    /// wall-clock time in an unknown zone, which [`Ts::semantic`] says.
    pub modified: Option<Ts>,
}

/// A file's modification time from the file system.
pub(crate) fn file_time(metadata: &fs::Metadata) -> Option<Ts> {
    let since = metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    Some(Ts::from_unix_micros(i64::try_from(since.as_micros()).ok()?))
}

/// Something evidence files can be read from.
pub trait Source {
    /// A short name for the source (its file or directory name).
    fn name(&self) -> &str;

    /// Every file in the source, sorted by path.
    ///
    /// # Errors
    /// When the source can't be listed.
    fn entries(&self) -> io::Result<Vec<SourceEntry>>;

    /// Run `f` with a reader over `entry`'s content.
    ///
    /// # Errors
    /// When the entry can't be opened, or `f` fails.
    fn with_reader(
        &self,
        entry: &SourceEntry,
        f: &mut dyn FnMut(&mut dyn Read) -> io::Result<()>,
    ) -> io::Result<()>;

    /// Up to `limit` bytes from the start of `entry`.
    ///
    /// # Errors
    /// When the entry can't be read.
    fn head(&self, entry: &SourceEntry, limit: usize) -> io::Result<Vec<u8>> {
        let mut head = Vec::with_capacity(limit);
        self.with_reader(entry, &mut |reader| {
            reader.take(limit as u64).read_to_end(&mut head).map(|_| ())
        })?;
        Ok(head)
    }

    /// SHA-256 of `entry`'s content, streamed. For zip entries, reading to
    /// the end also verifies the entry's CRC-32.
    ///
    /// # Errors
    /// When the entry can't be read or fails its integrity check.
    fn sha256(&self, entry: &SourceEntry) -> io::Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        self.with_reader(entry, &mut |reader| {
            io::copy(reader, &mut hasher).map(|_| ())
        })?;
        Ok(hasher.finalize())
    }

    /// The disk image the entries come from, when the source is one.
    fn container(&self) -> Option<&Container> {
        None
    }

    /// How the collection was encrypted, when it was.
    fn protection(&self) -> Option<Scheme> {
        None
    }
}

/// How much of the evidence becomes entries, beyond its live files.
///
/// Whoever opens the same evidence again to read its entries (an ingest's
/// workers, after its preview) must pass the same options, or entries the
/// preview listed may be missing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    /// The most Volume Shadow Copies read on each NTFS volume of a disk
    /// image, the newest kept: `None` (the default) reads them all, and
    /// `Some(0)` none. Each one read adds every file of its volume as it
    /// was, so a volume with many can multiply the entries; the ones left
    /// out are still listed in [`Container::shadow_copies`], with a
    /// warning.
    pub shadow_copy_limit: Option<usize>,
}

/// Open `path` as a source: a directory, a zip archive (encrypted
/// Velociraptor collections included), a disk image (E01, VHDX, raw), an
/// AD1 logical image, or a single file. A disk image's shadow copies are
/// all read: [`open_with`] chooses.
///
/// # Errors
/// When `path` can't be read. An encrypted collection opened without the
/// credentials it needs fails with a [`Locked`](crate::Locked) error.
pub fn open(path: &Path, credentials: &Credentials) -> io::Result<Box<dyn Source>> {
    open_with(path, credentials, &Options::default())
}

/// [`open`], with `options`.
///
/// # Errors
/// As [`open`].
pub fn open_with(
    path: &Path,
    credentials: &Credentials,
    options: &Options,
) -> io::Result<Box<dyn Source>> {
    let name = path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    if path.is_dir() {
        return Ok(Box::new(DirectorySource {
            root: path.to_owned(),
            name,
        }));
    }
    let head = read_head(path)?;
    if head.starts_with(AGE_SIGNATURE) {
        return open_age(path, name, credentials);
    }
    if head.starts_with(ZIP_SIGNATURE) {
        return open_zip(path, name, credentials);
    }
    if tar::is_tar(&head) {
        return Ok(Box::new(TarSource::open(path, name, false)?));
    }
    if common::gzip::is_gzip(&head) && tar::is_gzipped_tar(path) {
        return Ok(Box::new(TarSource::open(path, name, true)?));
    }
    if logical::is_ad1(&head) {
        return Ok(Box::new(logical::Ad1Source::open(path, &head, name)?));
    }
    if image::is_image(path, &head) {
        return Ok(Box::new(ImageSource::open(path, &head, name, options)?));
    }
    Ok(Box::new(FileSource {
        path: path.to_owned(),
        name,
    }))
}

/// Read-ahead for the decrypted inner collection: every read of it seeks
/// in the outer file, so read in large pieces.
const INNER_BUFFER: usize = 1 << 16;

/// A zip encrypted with age (the Sootmark collector's archives, to the
/// case's key), read in place: each chunk is decrypted as the zip reader
/// reaches it, and no plaintext is written out.
fn open_age(path: &Path, name: String, credentials: &Credentials) -> io::Result<Box<dyn Source>> {
    let text = credentials
        .age_identities
        .as_deref()
        .ok_or_else(|| Locked::error(Scheme::Age))?;
    let identities = age::parse_identities(text)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let decrypted =
        age::decrypt_seekable(File::open(path)?, &identities).map_err(|error| match error {
            age::Error::NoMatchingIdentity => io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the archive is encrypted to another key than the ones given",
            ),
            age::Error::Io(error) => error,
            other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
        })?;
    let archive = Archive::open(BufReader::with_capacity(INNER_BUFFER, decrypted))
        .map_err(|e| io::Error::new(e.kind(), format!("decrypted, but not a zip archive: {e}")))?;
    Ok(Box::new(ZipSource::new(
        archive,
        name,
        Some(Scheme::Age),
        None,
    )))
}

fn open_zip(path: &Path, name: String, credentials: &Credentials) -> io::Result<Box<dyn Source>> {
    let mut archive = Archive::open(BufReader::new(File::open(path)?))?;
    if let Some(protection) = protected::detect(&mut archive)? {
        let password = protection.password(credentials)?;
        let inner = archive.into_stored(protection.data, Some(&password))?;
        let inner = Archive::open(BufReader::with_capacity(INNER_BUFFER, inner))?;
        return Ok(Box::new(ZipSource::new(
            inner,
            name,
            Some(protection.scheme),
            None,
        )));
    }
    // A zip with encrypted entries (e.g. made with 7-Zip and a password):
    // check the password now rather than on the first entry read.
    let Some(encrypted) = archive
        .entries()
        .iter()
        .position(|e| e.encryption.is_some())
    else {
        return Ok(Box::new(ZipSource::new(archive, name, None, None)));
    };
    let password = credentials
        .password
        .as_ref()
        .ok_or_else(|| Locked::error(Scheme::Password))?
        .as_bytes()
        .to_vec();
    archive.reader_with_password(encrypted, &password)?;
    Ok(Box::new(ZipSource::new(
        archive,
        name,
        Some(Scheme::Password),
        Some(password),
    )))
}

const ZIP_SIGNATURE: &[u8; 4] = b"PK\x03\x04";
/// The first line of an age file.
const AGE_SIGNATURE: &[u8] = b"age-encryption.org/v1\n";
/// Enough of a file to recognise every container signature, and an AD1
/// segment's margin (its segment count).
const SIGNATURE_SIZE: u64 = 512;

fn read_head(path: &Path) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    File::open(path)?
        .take(SIGNATURE_SIZE)
        .read_to_end(&mut head)?;
    Ok(head)
}

/// A directory, walked recursively. Symbolic links are not followed.
struct DirectorySource {
    root: PathBuf,
    name: String,
}

impl DirectorySource {
    fn walk(&self, dir: &Path, entries: &mut Vec<SourceEntry>) -> io::Result<()> {
        for item in fs::read_dir(dir)? {
            let item = item?;
            let metadata = fs::symlink_metadata(item.path())?;
            if metadata.is_dir() {
                self.walk(&item.path(), entries)?;
            } else if metadata.is_file() {
                let relative = item
                    .path()
                    .strip_prefix(&self.root)
                    .map_err(io::Error::other)?
                    .to_owned();
                let path = relative
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                entries.push(SourceEntry {
                    path,
                    size: metadata.len(),
                    modified: file_time(&metadata),
                });
            }
        }
        Ok(())
    }
}

impl Source for DirectorySource {
    fn name(&self) -> &str {
        &self.name
    }

    fn entries(&self) -> io::Result<Vec<SourceEntry>> {
        let mut entries = Vec::new();
        self.walk(&self.root, &mut entries)?;
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    fn with_reader(
        &self,
        entry: &SourceEntry,
        f: &mut dyn FnMut(&mut dyn Read) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut file = BufReader::new(File::open(self.root.join(&entry.path))?);
        f(&mut file)
    }
}

/// A zip archive (zip64 included). Entries are streamed, never extracted to
/// disk; reading an entry to the end verifies its CRC-32.
struct ZipSource<R> {
    archive: RefCell<Archive<R>>,
    name: String,
    protection: Option<Scheme>,
    /// For zips whose entries are encrypted themselves.
    password: Option<Vec<u8>>,
}

impl<R: Read + Seek> ZipSource<R> {
    const fn new(
        archive: Archive<R>,
        name: String,
        protection: Option<Scheme>,
        password: Option<Vec<u8>>,
    ) -> Self {
        Self {
            archive: RefCell::new(archive),
            name,
            protection,
            password,
        }
    }

    fn index_of(&self, path: &str) -> io::Result<usize> {
        self.archive
            .borrow()
            .entries()
            .iter()
            .position(|e| e.name == path)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such entry in the archive"))
    }
}

impl<R: Read + Seek> Source for ZipSource<R> {
    fn name(&self) -> &str {
        &self.name
    }

    fn entries(&self) -> io::Result<Vec<SourceEntry>> {
        let archive = self.archive.borrow();
        let mut entries: Vec<SourceEntry> = archive
            .entries()
            .iter()
            .filter(|e| !e.is_directory())
            .map(|e| SourceEntry {
                path: e.name.clone(),
                size: e.size,
                modified: e.modified,
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
        let index = self.index_of(&entry.path)?;
        let mut archive = self.archive.borrow_mut();
        let mut reader = match &self.password {
            Some(password) => archive.reader_with_password(index, password)?,
            None => archive.reader(index)?,
        };
        f(&mut reader)
    }

    fn protection(&self) -> Option<Scheme> {
        self.protection
    }
}

/// A single loose file.
struct FileSource {
    path: PathBuf,
    name: String,
}

impl Source for FileSource {
    fn name(&self) -> &str {
        &self.name
    }

    fn entries(&self) -> io::Result<Vec<SourceEntry>> {
        let metadata = fs::metadata(&self.path)?;
        Ok(vec![SourceEntry {
            path: self.name.clone(),
            size: metadata.len(),
            modified: file_time(&metadata),
        }])
    }

    fn with_reader(
        &self,
        _entry: &SourceEntry,
        f: &mut dyn FnMut(&mut dyn Read) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut file = BufReader::new(File::open(&self.path)?);
        f(&mut file)
    }
}
