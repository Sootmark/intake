//! Tar archives (`.tar`, and gzipped: `.tar.gz`, `.tgz`) as sources: acquire
//! and UAC write their collections as tar.
//!
//! Headers are ustar (POSIX), with GNU long names (`L`) and pax extended
//! headers (`x`: `path`, `size`); global pax headers are ignored. Regular
//! files become entries; directories, links and devices don't hold content
//! and are left out. Paths that climb out (`..`) are left out
//! too; a leading `/` is dropped; and a later entry with the same path
//! replaces an earlier one, as tar itself does when extracting.
//!
//! A gzipped tar can't be read out of order, and entries are read out of
//! order (by several worker processes), so it is decompressed once into a
//! temporary file named after the archive (its path, size and modification
//! time) that every process reuses.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use common::gzip;
use common::sha256::Sha256;

use crate::source::{Source, SourceEntry};

const BLOCK: u64 = 512;
const NAME: std::ops::Range<usize> = 0..100;
const SIZE: std::ops::Range<usize> = 124..136;
const CHECKSUM: std::ops::Range<usize> = 148..156;
const TYPE: usize = 156;
const MAGIC: std::ops::Range<usize> = 257..262;
const PREFIX: std::ops::Range<usize> = 345..500;
/// Longest name a GNU or pax header may set, and largest pax header read.
const MAX_META: u64 = 1 << 20;

/// Whether `block` is a tar header: the ustar magic and a valid checksum.
pub(crate) fn is_tar(block: &[u8]) -> bool {
    block.len() >= BLOCK as usize && &block[MAGIC] == b"ustar" && checksum_ok(block)
}

/// Whether a gzip stream holds a tar: its first block, decompressed.
pub(crate) fn is_gzipped_tar(path: &Path) -> bool {
    let Ok(file) = File::open(path) else {
        return false;
    };
    let mut first = vec![0u8; BLOCK as usize];
    gzip::Decoder::new(BufReader::new(file))
        .read_exact(&mut first)
        .is_ok()
        && is_tar(&first)
}

fn checksum_ok(block: &[u8]) -> bool {
    let Some(stored) = octal(&block[CHECKSUM]) else {
        return false;
    };
    let sum: u64 = block[..BLOCK as usize]
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if CHECKSUM.contains(&i) {
                u64::from(b' ')
            } else {
                u64::from(b)
            }
        })
        .sum();
    sum == stored
}

/// An octal field, or GNU's base-256 form for large sizes.
fn octal(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        return field[1..]
            .iter()
            .try_fold(u64::from(field[0] & 0x7f), |n, &b| {
                n.checked_mul(256)?.checked_add(u64::from(b))
            });
    }
    let text = std::str::from_utf8(field).ok()?;
    let digits = text.trim_matches(|c: char| c == '\0' || c == ' ');
    if digits.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(digits, 8).ok()
}

fn text(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// A path inside the archive, `/`-separated and relative, or `None` when it
/// climbs out.
fn clean(path: &str) -> Option<String> {
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => return None,
            part => parts.push(part),
        }
    }
    // A leading `/` is dropped, as tar does when extracting.
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// The value of `key` in a pax extended header (`<len> key=value\n` records).
fn pax(data: &[u8], key: &str) -> Option<String> {
    let mut rest = data;
    while !rest.is_empty() {
        let space = rest.iter().position(|&b| b == b' ')?;
        let length: usize = std::str::from_utf8(&rest[..space]).ok()?.parse().ok()?;
        let record = rest.get(space + 1..length)?;
        let record = record.strip_suffix(b"\n").unwrap_or(record);
        let eq = record.iter().position(|&b| b == b'=')?;
        if &record[..eq] == key.as_bytes() {
            return Some(String::from_utf8_lossy(&record[eq + 1..]).into_owned());
        }
        rest = &rest[length..];
    }
    None
}

/// A tar archive's regular files: offset of their content, size.
struct Index {
    files: BTreeMap<String, (u64, u64)>,
}

fn index(file: &mut BufReader<File>, length: u64) -> io::Result<Index> {
    let mut files = BTreeMap::new();
    let mut at = 0u64;
    let mut long_name: Option<String> = None;
    let mut pax_path: Option<String> = None;
    let mut pax_size: Option<u64> = None;
    let mut header = [0u8; BLOCK as usize];
    while at + BLOCK <= length {
        file.seek(SeekFrom::Start(at))?;
        file.read_exact(&mut header)?;
        if header.iter().all(|&b| b == 0) {
            break;
        }
        if !checksum_ok(&header) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("tar: damaged header at offset {at}"),
            ));
        }
        let size = pax_size
            .take()
            .map_or_else(|| octal(&header[SIZE]), Some)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("tar: bad size at offset {at}"),
                )
            })?;
        let data = at + BLOCK;
        let next = data
            .checked_add(size.div_ceil(BLOCK) * BLOCK)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("tar: size past the end at offset {at}"),
                )
            })?;
        let meta = |file: &mut BufReader<File>| -> io::Result<Vec<u8>> {
            let mut bytes = vec![0u8; usize::try_from(size.min(MAX_META)).unwrap_or(0)];
            file.read_exact(&mut bytes)?;
            Ok(bytes)
        };
        match header[TYPE] {
            b'L' => long_name = Some(text(&meta(file)?)),
            b'x' => {
                let data = meta(file)?;
                pax_path = pax(&data, "path");
                pax_size = pax(&data, "size").and_then(|s| s.parse().ok());
            }
            b'0' | b'\0' | b'7' => {
                let name = match (pax_path.take(), long_name.take()) {
                    (Some(path), _) | (None, Some(path)) => path,
                    (None, None) => {
                        let (prefix, name) = (text(&header[PREFIX]), text(&header[NAME]));
                        if prefix.is_empty() {
                            name
                        } else {
                            format!("{prefix}/{name}")
                        }
                    }
                };
                if let Some(path) = clean(&name) {
                    if next > length {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!("tar: {path} is cut short"),
                        ));
                    }
                    files.insert(path, (data, size));
                }
            }
            // Directories, links, devices, global pax headers.
            _ => {
                long_name = None;
                pax_path = None;
            }
        }
        at = next;
    }
    Ok(Index { files })
}

/// A tar archive, read in place (or, gzipped, from its decompressed copy).
pub(crate) struct TarSource {
    tar: PathBuf,
    name: String,
    index: Index,
}

impl TarSource {
    pub(crate) fn open(path: &Path, name: String, gzipped: bool) -> io::Result<Self> {
        let tar = if gzipped {
            decompressed(path)?
        } else {
            path.to_owned()
        };
        let length = fs::metadata(&tar)?.len();
        let index = index(&mut BufReader::new(File::open(&tar)?), length)?;
        Ok(Self { tar, name, index })
    }
}

/// The decompressed copy of a gzipped tar, made once and shared.
fn decompressed(path: &Path) -> io::Result<PathBuf> {
    let metadata = fs::metadata(path)?;
    let modified = metadata
        .modified()?
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let identity = format!(
        "{}\n{}\n{modified}",
        path.canonicalize()?.display(),
        metadata.len()
    );
    let digest = Sha256::digest(identity.as_bytes());
    let dir = std::env::temp_dir().join("sootmark-tar");
    fs::create_dir_all(&dir)?;
    let target = dir.join(format!("{}.tar", common::hex::encode(&digest[..16])));
    if target.exists() {
        return Ok(target);
    }
    // Written aside, then moved into place: a reader never sees half of it,
    // and two processes decompressing at once both end with a whole copy.
    let partial = dir.join(format!(
        "{}.{}.partial",
        common::hex::encode(&digest[..16]),
        std::process::id()
    ));
    let result = (|| {
        let mut out = io::BufWriter::new(File::create(&partial)?);
        io::copy(
            &mut gzip::Decoder::new(BufReader::new(File::open(path)?)),
            &mut out,
        )?;
        out.flush()?;
        fs::rename(&partial, &target)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result.map(|()| target)
}

impl Source for TarSource {
    fn name(&self) -> &str {
        &self.name
    }

    fn entries(&self) -> io::Result<Vec<SourceEntry>> {
        Ok(self
            .index
            .files
            .iter()
            .map(|(path, &(_, size))| SourceEntry {
                path: path.clone(),
                size,
            })
            .collect())
    }

    fn with_reader(
        &self,
        entry: &SourceEntry,
        f: &mut dyn FnMut(&mut dyn Read) -> io::Result<()>,
    ) -> io::Result<()> {
        let &(offset, size) = self.index.files.get(&entry.path).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} isn't in {}", entry.path, self.name),
            )
        })?;
        let mut file = BufReader::new(File::open(&self.tar)?);
        file.seek(SeekFrom::Start(offset))?;
        f(&mut file.take(size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pax record: its length counts itself.
    fn record(key: &str, value: &str) -> Vec<u8> {
        let body = format!(" {key}={value}\n");
        let mut length = body.len() + 1;
        while format!("{length}{body}").len() != length {
            length += 1;
        }
        format!("{length}{body}").into_bytes()
    }

    #[test]
    fn fields() {
        assert_eq!(octal(b"0000644\0"), Some(0o644));
        assert_eq!(octal(b"00000000017 "), Some(15));
        assert_eq!(
            octal(&[0x80, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]),
            Some(1 << 32)
        );
        assert_eq!(clean("./C/Windows/x"), Some("C/Windows/x".to_owned()));
        assert_eq!(clean("a/../../etc/passwd"), None);
        assert_eq!(clean("/etc/passwd"), Some("etc/passwd".to_owned()));
        let records = [record("path", "very/long/name/here"), record("size", "42")].concat();
        assert_eq!(
            pax(&records, "path").as_deref(),
            Some("very/long/name/here")
        );
        assert_eq!(pax(&records, "size").as_deref(), Some("42"));
        assert_eq!(pax(&records, "mtime"), None);
    }
}
