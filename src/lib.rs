//! Evidence intake.
//!
//! Point intake at a directory, a zip (encrypted Velociraptor collections
//! included), a disk image or a single file. It lists the files, recognises the collector's layout (KAPE, Velociraptor) to recover the
//! paths files had on the host, proposes a host name, and asks every parser
//! adapter which files it can read, without parsing anything yet. The result
//! is the detection preview the analyst confirms before ingest.

mod collection;
mod detect;
mod image;
mod layout;
mod logical;
mod manifest;
mod path;
mod preview;
mod protected;
mod source;
#[cfg(feature = "x509")]
mod x509;

pub use collection::{
    check_hashes, CollectionLog, Failure, HashCheck, HashMismatch, LogLine, Outcome, PartialFile,
    RecordedHash,
};
pub use detect::{detect, Detected, PROBE_SIZE};
pub use image::{Container, ContainerFormat};
pub use layout::{recognise, HintSource, HostHint, Layout, LayoutKind};
pub use manifest::{manifest, ManifestEntry};
pub use path::HostPath;
pub use preview::{preview, Preview, Tally};
pub use protected::{Credentials, Locked, Scheme};
pub use source::{open, Source, SourceEntry};
