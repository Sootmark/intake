//! The detection preview shown before anything is parsed (UX spec §4.2).

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use common::json::Json;
use model::adapter::Adapter;

use crate::collection::{self, CollectionLog};
use crate::detect::{detect, Detected};
use crate::image::Container;
use crate::layout::{self, Layout};
use crate::protected::{Credentials, Scheme};
use crate::source;

/// Count and size of a group of files.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    /// Number of files.
    pub files: u64,
    /// Total bytes.
    pub bytes: u64,
}

impl Tally {
    fn add(&mut self, size: u64) {
        self.files += 1;
        self.bytes += size;
    }

    fn to_json(self) -> Json {
        Json::object([
            ("files", Json::from(self.files)),
            ("bytes", Json::from(self.bytes)),
        ])
    }
}

/// What a source contains and what will be parsed, before parsing.
#[derive(Debug, Clone)]
pub struct Preview {
    /// Source name.
    pub source: String,
    /// The disk image, when the source is one.
    pub container: Option<Container>,
    /// How the collection was encrypted, when it was.
    pub protection: Option<Scheme>,
    /// Recognised layout and host hint.
    pub layout: Layout,
    /// What the collector recorded about the collection, when it did.
    pub collection_log: Option<CollectionLog>,
    /// Every file.
    pub total: Tally,
    /// Files each parser will read.
    pub by_parser: BTreeMap<&'static str, Tally>,
    /// Files no parser recognised.
    pub unrecognised: Tally,
    /// Files that couldn't be read (see [`Detected::unreadable`]).
    pub unreadable: Tally,
    /// Per-file detail.
    pub files: Vec<Detected>,
}

impl Preview {
    /// The preview as JSON.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("source", Json::from(self.source.as_str())),
            (
                "encryption",
                self.protection
                    .map_or(Json::Null, |scheme| Json::from(scheme.id())),
            ),
            (
                "container",
                self.container
                    .as_ref()
                    .map_or(Json::Null, Container::to_json),
            ),
            ("layout", self.layout.to_json()),
            (
                "collection_log",
                self.collection_log
                    .as_ref()
                    .map_or(Json::Null, CollectionLog::to_json),
            ),
            ("total", self.total.to_json()),
            (
                "by_parser",
                Json::object(
                    self.by_parser
                        .iter()
                        .map(|(parser, tally)| (*parser, tally.to_json())),
                ),
            ),
            ("unrecognised", self.unrecognised.to_json()),
            ("unreadable", self.unreadable.to_json()),
            (
                "files",
                Json::Array(self.files.iter().map(Detected::to_json).collect()),
            ),
        ])
    }
}

/// Build the preview for the evidence at `path`, opening encrypted
/// collections with `credentials`.
///
/// # Errors
/// When the evidence can't be opened or read; a [`Locked`](crate::Locked)
/// error when it's encrypted and `credentials` lack what it needs.
pub fn preview(
    path: &Path,
    adapters: &[&dyn Adapter],
    credentials: &Credentials,
) -> io::Result<Preview> {
    let source = source::open(path, credentials)?;
    let entries = source.entries()?;
    let layout = layout::recognise(source.as_ref(), &entries);
    let collection_log = collection::read(source.as_ref(), &layout, &entries);
    let files = detect(source.as_ref(), &layout, &entries, adapters)?;
    let mut total = Tally::default();
    let mut by_parser: BTreeMap<&'static str, Tally> = BTreeMap::new();
    let mut unrecognised = Tally::default();
    let mut unreadable = Tally::default();
    for file in &files {
        total.add(file.size);
        match (file.parser, &file.unreadable) {
            (_, Some(_)) => unreadable.add(file.size),
            (Some(parser), None) => by_parser.entry(parser).or_default().add(file.size),
            (None, None) => unrecognised.add(file.size),
        }
    }
    Ok(Preview {
        source: source.name().to_owned(),
        container: source.container().cloned(),
        protection: source.protection(),
        layout,
        collection_log,
        total,
        by_parser,
        unrecognised,
        unreadable,
        files,
    })
}
