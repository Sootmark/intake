//! Tar collections (`tests/fixtures/make-tar-collections.py`): acquire's
//! layouts (pax and GNU tar, gzipped or not) and UAC's, mapped to the paths
//! the files had on their hosts; long names, links and directories, a file
//! written twice, and a damaged header.

use std::path::Path;

use adapters::evtx::EvtxAdapter;
use model::adapter::Adapter;
use sootmark_intake::{open, preview, Credentials, HintSource, LayoutKind, Preview};

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tar")
        .join(name)
}

fn adapters() -> Vec<&'static dyn Adapter> {
    vec![&EvtxAdapter]
}

fn host_paths(preview: &Preview) -> Vec<(String, Option<String>)> {
    preview
        .files
        .iter()
        .map(|f| {
            (
                f.path.clone(),
                f.host_path.as_ref().map(ToString::to_string),
            )
        })
        .collect()
}

#[test]
fn acquire_gzipped_pax() {
    let path = fixture("acquire-ws01.tar.gz");
    let preview = preview(&path, &adapters(), &Credentials::default()).unwrap();
    assert_eq!(preview.layout.kind, LayoutKind::Acquire);
    let long = "Users/alice/AppData/Local/Microsoft/Windows/PowerShell/PSReadLine/very-long-folder-name/very-long-folder-name/very-long-folder-name/ConsoleHost_history.txt";
    assert_eq!(
        host_paths(&preview),
        [
            (
                format!("fs/C:/{long}"),
                Some(format!(r"C:\{}", long.replace('/', r"\")))
            ),
            (
                "fs/C:/Windows/System32/config/SYSTEM".to_owned(),
                Some(r"C:\Windows\System32\config\SYSTEM".to_owned())
            ),
            (
                "fs/C:/Windows/System32/winevt/Logs/Security.evtx".to_owned(),
                Some(r"C:\Windows\System32\winevt\Logs\Security.evtx".to_owned())
            ),
        ],
        "files only (no directory, no link), the long path whole"
    );
    assert_eq!(preview.by_parser["evtx"].files, 1);
    // The later copy of a file written twice is the one read.
    let source = open(&path, &Credentials::default()).unwrap();
    let entries = source.entries().unwrap();
    let system = entries.iter().find(|e| e.path.ends_with("SYSTEM")).unwrap();
    let mut text = String::new();
    source
        .with_reader(system, &mut |r| r.read_to_string(&mut text).map(|_| ()))
        .unwrap();
    assert_eq!(text, "regf");
    // A second open reuses the decompressed copy.
    let again = open(&path, &Credentials::default()).unwrap();
    assert_eq!(again.entries().unwrap(), entries);
}

#[test]
fn acquire_old_layout_gnu_tar() {
    let preview = preview(
        &fixture("acquire-old.tar"),
        &adapters(),
        &Credentials::default(),
    )
    .unwrap();
    assert_eq!(preview.layout.kind, LayoutKind::Acquire);
    let paths = host_paths(&preview);
    assert!(paths.contains(&(
        "sysvol/Windows/System32/winevt/Logs/System.evtx".to_owned(),
        Some(r"C:\Windows\System32\winevt\Logs\System.evtx".to_owned())
    )));
    let notes = paths
        .iter()
        .find(|(p, _)| p.ends_with("notes.txt"))
        .unwrap();
    assert_eq!(
        notes.0,
        format!("sysvol/Users/bob/{}notes.txt", "deep/".repeat(25)),
        "GNU long name"
    );
}

#[test]
fn uac_unix_paths_and_hostname() {
    let preview = preview(
        &fixture("uac-srv-web01.tar.gz"),
        &adapters(),
        &Credentials::default(),
    )
    .unwrap();
    assert_eq!(preview.layout.kind, LayoutKind::Uac);
    let hint = preview.layout.host_hint.as_ref().unwrap();
    assert_eq!(
        (hint.name.as_str(), hint.source),
        ("srv-web01", HintSource::CollectorMetadata)
    );
    let paths = host_paths(&preview);
    assert!(paths.contains(&(
        "[root]/etc/passwd".to_owned(),
        Some("/etc/passwd".to_owned())
    )));
    assert!(paths.contains(&(
        "[root]/var/log/auth.log".to_owned(),
        Some("/var/log/auth.log".to_owned())
    )));
    assert!(
        paths.contains(&("uac.log".to_owned(), None)),
        "the collector's own files have no host path"
    );
}

#[test]
fn a_damaged_header_is_an_error() {
    let error = open(&fixture("damaged.tar"), &Credentials::default())
        .err()
        .unwrap();
    assert!(error.to_string().contains("damaged header"), "{error}");
}

mod damage {
    use proptest::prelude::*;
    use sootmark_intake::{open, Credentials};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        /// Any damage: opened and read, or refused; never a panic.
        #[test]
        fn never_panics(flips in proptest::collection::vec((0usize..10_240, any::<u8>()), 1..8), cut in 512usize..10_240) {
            let mut data = std::fs::read(super::fixture("acquire-old.tar")).unwrap();
            for (at, byte) in flips {
                data[at] = byte;
            }
            data.truncate(cut);
            let dir = std::env::temp_dir().join(format!("intake-tar-damage-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("damaged.tar");
            std::fs::write(&path, &data).unwrap();
            if let Ok(source) = open(&path, &Credentials::default()) {
                for entry in source.entries().unwrap_or_default() {
                    let _ = source.with_reader(&entry, &mut |r| r.read_to_end(&mut Vec::new()).map(|_| ()));
                }
            }
        }
    }
}
