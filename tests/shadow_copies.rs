//! Intake on dfVFS's VSS test volume (Apache-2.0, `tests/fixtures/dfvfs/`,
//! stored gzip-compressed and decompressed for each test): a bare NTFS
//! volume, with no partition table, and two shadow copies taken on 1 May
//! 2021. `sootmark-vss` checks each snapshot's view against libvshadow;
//! here, each one's files become entries beside the live volume's.
//!
//! The volume holds two files named after the snapshots: `vss1`, written
//! between the two snapshots, so in the second (index 1, `vss2/`) and the
//! live volume; and `vss2`, written after the second, so only in the live
//! volume.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use adapters::evtx::EvtxAdapter;
use common::json::Json;
use sootmark_intake::{
    open, open_with, preview, Credentials, LayoutKind, Options, Source, SourceEntry,
};

mod support;
use support::TempDir;

/// The live volume's files: no drive letter, as it holds no `Windows`.
const LIVE: &str = "vol0/";
/// The oldest snapshot's files (index 0).
const FIRST: &str = "vss1/vol0/";
/// The newest snapshot's files (index 1).
const SECOND: &str = "vss2/vol0/";
/// The snapshots' store files, as `vss.raw`'s catalog names them.
const FIRST_STORE: &str = "de81cc22-aa8b-11eb-9339-8cdcd4557abc";
const SECOND_STORE: &str = "de81cc2b-aa8b-11eb-9339-8cdcd4557abc";

/// `vss.raw`, decompressed into `dir`, cut to its first `len` bytes.
fn volume(dir: &TempDir, len: Option<usize>) -> PathBuf {
    let compressed = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dfvfs/vss.raw.gz");
    let mut data = Vec::new();
    common::gzip::Decoder::new(fs::read(compressed).unwrap().as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data.truncate(len.unwrap_or(data.len()));
    let path = dir.path().join("vss.raw");
    fs::write(&path, data).unwrap();
    path
}

fn paths_under<'e>(entries: &'e [SourceEntry], prefix: &str) -> Vec<&'e str> {
    entries
        .iter()
        .filter_map(|e| e.path.strip_prefix(prefix))
        .collect()
}

fn content(source: &dyn Source, entries: &[SourceEntry], path: &str) -> Vec<u8> {
    let entry = entries.iter().find(|e| e.path == path).unwrap();
    source.head(entry, 1 << 10).unwrap()
}

#[test]
fn every_shadow_copy_is_a_volume_of_its_own() {
    let dir = TempDir::new().unwrap();
    let source = open(&volume(&dir, None), &Credentials::default()).unwrap();
    let entries = source.entries().unwrap();
    let (live, first, second) = (
        paths_under(&entries, LIVE),
        paths_under(&entries, FIRST),
        paths_under(&entries, SECOND),
    );
    assert_eq!((live.len(), first.len(), second.len()), (31, 28, 30));
    assert_eq!(entries.len(), live.len() + first.len() + second.len());

    let has = |files: &[&str], name| files.contains(&name);
    assert!(has(&live, "vss1") && has(&second, "vss1") && !has(&first, "vss1"));
    assert!(has(&live, "vss2") && !has(&second, "vss2") && !has(&first, "vss2"));
    for name in ["passwords.txt", "a_directory/a_file", "$MFT"] {
        assert!(has(&live, name) && has(&first, name) && has(&second, name));
    }
    let old = content(source.as_ref(), &entries, "vss2/vol0/vss1");
    assert!(!old.is_empty());
    assert_eq!(old, content(source.as_ref(), &entries, "vol0/vss1"));

    // The first snapshot's store file as that snapshot kept it, 32 MiB,
    // shrunk since on the live volume: each view is read, not the volume.
    let store = format!(
        "System Volume Information/{{{FIRST_STORE}}}{{3808876b-c176-4e48-b7ae-04046e6cc752}}"
    );
    let size = |prefix: &str| {
        let path = format!("{prefix}{store}");
        entries.iter().find(|e| e.path == path).unwrap().size
    };
    assert_eq!(
        (size(FIRST), size(SECOND), size(LIVE)),
        (33_554_432, 33_554_432, 425_984)
    );
}

#[test]
fn the_container_lists_each_shadow_copy() {
    let dir = TempDir::new().unwrap();
    let source = open(&volume(&dir, None), &Credentials::default()).unwrap();
    let container = source.container().unwrap();
    assert!(container.warnings.is_empty(), "{:?}", container.warnings);
    let json = container.to_json();
    assert_eq!(
        json.get("shadow_copies").unwrap().to_string(),
        format!(
            "[{{\"volume\":\"vol0\",\"index\":0,\"path\":\"vss1/vol0\",\
             \"created\":\"2021-05-01T17:40:03.2230304Z\",\"store_id\":\"{FIRST_STORE}\",\
             \"entries\":28}},\
             {{\"volume\":\"vol0\",\"index\":1,\"path\":\"vss2/vol0\",\
             \"created\":\"2021-05-01T17:41:28.2249863Z\",\"store_id\":\"{SECOND_STORE}\",\
             \"entries\":30}}]"
        )
    );
}

#[test]
fn shadow_copy_files_keep_the_live_host_path() {
    let dir = TempDir::new().unwrap();
    let preview = preview(
        &volume(&dir, None),
        &[&EvtxAdapter],
        &Credentials::default(),
    )
    .unwrap();
    assert_eq!(preview.layout.kind, LayoutKind::DiskImage);
    let file = |path: &str| preview.files.iter().find(|f| f.path == path).unwrap();
    let (old, live) = (file("vss2/vol0/vss1"), file("vol0/vss1"));
    let (old_host, live_host) = (
        old.host_path.as_ref().unwrap(),
        live.host_path.as_ref().unwrap(),
    );
    assert_eq!(old_host.to_string(), r"\vss1");
    assert_eq!(old_host.to_string(), live_host.to_string());
    assert_eq!(
        (old_host.shadow_copy(), live_host.shadow_copy()),
        (Some(1), None)
    );
    assert_ne!(old_host, live_host);
    let json = old.to_json();
    assert_eq!(json.get("shadow_copy").and_then(Json::as_u64), Some(1));
    assert_eq!(
        json.get("path").and_then(Json::as_str),
        Some("vss2/vol0/vss1")
    );
}

#[test]
fn a_limit_reads_only_the_newest() {
    let dir = TempDir::new().unwrap();
    let path = volume(&dir, None);
    let with_limit = |limit| {
        let options = Options {
            shadow_copy_limit: Some(limit),
        };
        open_with(&path, &Credentials::default(), &options).unwrap()
    };

    let newest = with_limit(1);
    let entries = newest.entries().unwrap();
    assert!(paths_under(&entries, FIRST).is_empty());
    assert_eq!(paths_under(&entries, SECOND).len(), 30);
    let container = newest.container().unwrap();
    let read: Vec<Option<u64>> = container.shadow_copies.iter().map(|s| s.entries).collect();
    assert_eq!(read, [None, Some(30)]);
    assert_eq!(
        container.warnings,
        ["1 of the 2 shadow copies of volume vol0 not read: only the newest 1 were asked for"]
    );

    let none = with_limit(0);
    let entries = none.entries().unwrap();
    assert!(entries.iter().all(|e| e.path.starts_with(LIVE)));
    assert_eq!(entries.len(), 31);
    assert_eq!(none.container().unwrap().shadow_copies.len(), 2);
}

#[test]
fn damaged_shadow_copies_are_warnings() {
    // Cut short of the stores' block lists and bitmaps: the live volume's
    // metadata is all in the first 30 MiB.
    let dir = TempDir::new().unwrap();
    let source = open(&volume(&dir, Some(30 << 20)), &Credentials::default()).unwrap();
    let entries = source.entries().unwrap();
    assert_eq!(paths_under(&entries, LIVE).len(), 31);
    let warnings = &source.container().unwrap().warnings;
    assert!(!warnings.is_empty());
    assert!(
        warnings.iter().all(|w| w.starts_with("shadow cop")),
        "{warnings:?}"
    );
}
