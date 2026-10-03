//! A file that can't be read (here, without read permission; in images,
//! an encrypted or damaged stream) is reported with why, and the rest of
//! the evidence is detected as usual.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use adapters::evtx::EvtxAdapter;
use sootmark_intake::{preview, Credentials};

mod support;
use support::TempDir;

#[test]
fn an_unreadable_file_is_reported_not_fatal() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("notes.txt"), b"readable").unwrap();
    let locked = dir.path().join("locked.evtx");
    fs::write(&locked, b"ElfFile\0").unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(&locked).is_ok() {
        eprintln!("skipped: running with permission to read anything");
        return;
    }
    let result = preview(dir.path(), &[&EvtxAdapter], &Credentials::default());
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o600)).unwrap();
    let preview = result.unwrap();
    assert_eq!(preview.total.files, 2);
    assert_eq!(preview.unreadable.files, 1);
    assert_eq!(preview.unrecognised.files, 1);
    let file = preview
        .files
        .iter()
        .find(|f| f.path == "locked.evtx")
        .unwrap();
    assert!(file.parser.is_none());
    assert!(file
        .unreadable
        .as_deref()
        .is_some_and(|why| !why.is_empty()));
}
