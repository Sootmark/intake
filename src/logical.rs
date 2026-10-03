//! AD1 logical images (FTK Imager custom content images) as evidence
//! sources: each file in the image becomes an entry, read straight from
//! the image without extraction.
//!
//! An image's top items are the sources it was made from (a volume such
//! as `…:Partition 2 [50649MB]:NONAME [NTFS]`, with `[root]` under it).
//! Paths follow the rule disk images do (see `image`): the source holding
//! `Windows` gets `C/`, any other `vol<n>/` in the image's order. FTK's
//! file slack pseudo-files (`….FileSlack`) aren't files on the volume and
//! aren't listed.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

use ad1::Image;

use crate::image::{Container, ContainerFormat};
use crate::source::{Source, SourceEntry};

const SIGNATURE: &[u8] = b"ADSEGMENTEDFILE";
const ENCRYPTED_SIGNATURE: &[u8] = b"ADCRYPT";
/// FTK lists a file's slack as an item of its own, with this suffix.
const SLACK_SUFFIX: &str = ".FileSlack";
/// FTK names a volume's top folder so.
const VOLUME_ROOT: &str = "[root]";

/// Whether `head` starts an AD1 image (encrypted ones included, so they're
/// refused with a reason rather than read as a plain file).
pub(crate) fn is_ad1(head: &[u8]) -> bool {
    head.starts_with(SIGNATURE) || head.starts_with(ENCRYPTED_SIGNATURE)
}

/// The segments of the image whose first segment is `first`: `x.ad1`,
/// `x.ad2`, … as many as its margin says.
fn segments(first: &Path, head: &[u8]) -> io::Result<Vec<PathBuf>> {
    let count = head
        .get(28..32)
        .and_then(|b| b.try_into().ok())
        .map_or(1, u32::from_le_bytes)
        .max(1);
    let stem = first.with_extension("");
    (1..=count)
        .map(|n| {
            let path = if n == 1 {
                first.to_owned()
            } else {
                stem.with_extension(format!("ad{n}"))
            };
            if path.is_file() {
                Ok(path)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("AD1 segment {n} of {count} missing: {}", path.display()),
                ))
            }
        })
        .collect()
}

/// An AD1 image seen as a source of files.
pub(crate) struct Ad1Source {
    image: RefCell<Image<BufReader<File>>>,
    entries: Vec<SourceEntry>,
    /// Entry path to item index.
    index: HashMap<String, usize>,
    container: Container,
    name: String,
}

impl Ad1Source {
    pub(crate) fn open(path: &Path, head: &[u8], name: String) -> io::Result<Self> {
        if head.starts_with(ENCRYPTED_SIGNATURE) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "encrypted AD1 image: not supported yet",
            ));
        }
        let readers = segments(path, head)?
            .iter()
            .map(|p| File::open(p).map(BufReader::new))
            .collect::<io::Result<_>>()?;
        let image = Image::open(readers)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let prefixes = prefixes(&image);
        let mut entries = Vec::new();
        let mut index = HashMap::new();
        for (i, item) in image.items.iter().enumerate() {
            if !item.has_content() || item.is_folder() || item.name.ends_with(SLACK_SUFFIX) {
                continue;
            }
            let Some(path) = entry_path(&image, i, &prefixes) else {
                continue;
            };
            index.insert(path.clone(), i);
            entries.push(SourceEntry {
                path,
                size: item.size,
            });
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        let mut acquisition = vec![("source", image.source.clone())];
        acquisition.extend(
            image
                .items
                .iter()
                .filter(|i| i.parent.is_none())
                .map(|i| ("contains", i.name.clone())),
        );
        let container = Container {
            format: ContainerFormat::Ad1,
            media_size: entries.iter().map(|e| e.size).sum(),
            stored_md5: None,
            stored_sha1: None,
            acquisition,
            volume_layout: prefixes.values().any(|p| !p.is_empty()),
            warnings: image.problems.clone(),
        };
        Ok(Self {
            image: RefCell::new(image),
            entries,
            index,
            container,
            name,
        })
    }
}

/// The top item an item is under.
fn top(image: &Image<BufReader<File>>, mut index: usize) -> usize {
    while let Some(parent) = image.items[index].parent {
        index = parent;
    }
    index
}

/// Each top item's path prefix (see the module documentation).
fn prefixes(image: &Image<BufReader<File>>) -> HashMap<usize, String> {
    let tops: Vec<usize> = (0..image.items.len())
        .filter(|&i| image.items[i].parent.is_none())
        .collect();
    let system = tops.iter().copied().find(|&t| {
        (0..image.items.len()).any(|i| {
            top(image, i) == t
                && relative(image, t, i).is_some_and(|r| r.eq_ignore_ascii_case("Windows"))
        })
    });
    tops.iter()
        .enumerate()
        .map(|(n, &t)| {
            let prefix = if Some(t) == system {
                "C".to_owned()
            } else {
                format!("vol{}", n + 1)
            };
            (t, prefix)
        })
        .collect()
}

/// The item's path under top item `top`, `[root]` left out.
fn relative(image: &Image<BufReader<File>>, top: usize, index: usize) -> Option<&str> {
    let rest = image.items[index]
        .path
        .strip_prefix(&image.items[top].path)?
        .trim_start_matches('/');
    Some(
        rest.strip_prefix(VOLUME_ROOT)
            .map_or(rest, |r| r.trim_start_matches('/')),
    )
}

/// `prefix/a/b/file`: the item's path under its volume's prefix.
fn entry_path(
    image: &Image<BufReader<File>>,
    index: usize,
    prefixes: &HashMap<usize, String>,
) -> Option<String> {
    let top = top(image, index);
    Some(format!(
        "{}/{}",
        prefixes.get(&top)?,
        relative(image, top, index)?
    ))
}

impl Source for Ad1Source {
    fn name(&self) -> &str {
        &self.name
    }

    fn entries(&self) -> io::Result<Vec<SourceEntry>> {
        Ok(self.entries.clone())
    }

    fn with_reader(
        &self,
        entry: &SourceEntry,
        f: &mut dyn FnMut(&mut dyn Read) -> io::Result<()>,
    ) -> io::Result<()> {
        let &item = self
            .index
            .get(&entry.path)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such file in the image"))?;
        let mut image = self.image.borrow_mut();
        let mut content = image
            .content(item)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        f(&mut content)
    }

    fn container(&self) -> Option<&Container> {
        Some(&self.container)
    }
}
