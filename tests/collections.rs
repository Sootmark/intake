//! Intake on synthetic collections laid out the way KAPE and Velociraptor
//! write them.

use std::fs;
use std::path::Path;

use adapters::evtx::EvtxAdapter;
use model::adapter::Adapter;
use sootmark_intake::{preview, Credentials, HintSource, LayoutKind, Preview};

mod support;
use support::TempDir;

/// Enough of an event log for detection: the file signature.
const EVTX_BYTES: &[u8] = b"ElfFile\0 rest of the header";
const SECURITY_LOG: &str = r"C:\Windows\System32\winevt\Logs\Security.evtx";

fn adapters() -> Vec<&'static dyn Adapter> {
    vec![&EvtxAdapter]
}

fn write_file(root: &Path, relative: &str, content: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn kape_folder(root: &Path) {
    write_file(
        root,
        "C/Windows/System32/winevt/Logs/Security.evtx",
        EVTX_BYTES,
    );
    write_file(root, "C/Windows/System32/config/SYSTEM", b"regf");
    write_file(root, "2026-09-28T101500_ConsoleLog.txt", b"KAPE log");
}

fn host_path_of(preview: &Preview, stored: &str) -> Option<String> {
    let file = preview
        .files
        .iter()
        .find(|f| f.path.ends_with(stored))
        .expect("file listed");
    file.host_path.as_ref().map(ToString::to_string)
}

#[test]
fn kape_folder_maps_drive_folders_to_host_paths() {
    let dir = TempDir::new().unwrap();
    kape_folder(dir.path());
    let preview = preview(dir.path(), &adapters(), &Credentials::default()).unwrap();
    assert_eq!(preview.layout.kind, LayoutKind::Kape);
    assert_eq!(preview.layout.host_hint, None);
    assert_eq!(
        host_path_of(&preview, "Security.evtx").as_deref(),
        Some(SECURITY_LOG)
    );
    assert_eq!(host_path_of(&preview, "ConsoleLog.txt"), None);
    assert_eq!(preview.total.files, 3);
    assert_eq!(preview.by_parser["evtx"].files, 1);
    assert_eq!(preview.unrecognised.files, 2);
}

#[test]
fn a_wrapping_folder_becomes_the_host_hint() {
    let dir = TempDir::new().unwrap();
    kape_folder(&dir.path().join("WS-042"));
    let preview = preview(dir.path(), &adapters(), &Credentials::default()).unwrap();
    assert_eq!(preview.layout.kind, LayoutKind::Kape);
    assert_eq!(preview.layout.root.as_deref(), Some("WS-042"));
    let hint = preview.layout.host_hint.as_ref().unwrap();
    assert_eq!(
        (hint.name.as_str(), hint.source),
        ("WS-042", HintSource::FolderName)
    );
    assert_eq!(
        host_path_of(&preview, "Security.evtx").as_deref(),
        Some(SECURITY_LOG)
    );
}

#[test]
fn velociraptor_zip_decodes_paths_and_reads_the_hostname() {
    // Built by Python's zipfile with the layout Velociraptor writes.
    let zip_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/Collection-FS01.zip");
    let preview = preview(&zip_path, &adapters(), &Credentials::default()).unwrap();
    assert_eq!(preview.layout.kind, LayoutKind::Velociraptor);
    let hint = preview.layout.host_hint.as_ref().unwrap();
    assert_eq!(
        (hint.name.as_str(), hint.source),
        ("FS01", HintSource::CollectorMetadata)
    );
    assert_eq!(
        host_path_of(&preview, "Security.evtx").as_deref(),
        Some(SECURITY_LOG)
    );
    assert_eq!(host_path_of(&preview, "$MFT").as_deref(), Some(r"C:\$MFT"));
    assert_eq!(host_path_of(&preview, "Pslist.json"), None);
    assert_eq!(preview.by_parser["evtx"].files, 1);
}

#[test]
fn loose_files_are_detected_by_content() {
    let dir = TempDir::new().unwrap();
    write_file(dir.path(), "evidence/renamed.bin", EVTX_BYTES);
    write_file(dir.path(), "evidence/notes.txt", b"analyst notes");
    let preview = preview(dir.path(), &adapters(), &Credentials::default()).unwrap();
    assert_eq!(preview.layout.kind, LayoutKind::Loose);
    assert_eq!(
        preview.by_parser["evtx"].files, 1,
        "detected by signature despite the name"
    );
}

#[test]
fn a_single_file_is_a_source() {
    let dir = TempDir::new().unwrap();
    write_file(dir.path(), "Security.evtx", EVTX_BYTES);
    let preview = preview(
        &dir.path().join("Security.evtx"),
        &adapters(),
        &Credentials::default(),
    )
    .unwrap();
    assert_eq!(preview.total.files, 1);
    assert_eq!(preview.by_parser["evtx"].files, 1);
}

#[test]
fn manifest_hashes_every_file() {
    let dir = TempDir::new().unwrap();
    kape_folder(dir.path());
    let source = sootmark_intake::open(dir.path(), &Credentials::default()).unwrap();
    let entries = source.entries().unwrap();
    let layout = sootmark_intake::recognise(source.as_ref(), &entries);
    let manifest = sootmark_intake::manifest(source.as_ref(), &layout, &entries).unwrap();
    assert_eq!(manifest.len(), 3);
    let system = manifest
        .iter()
        .find(|e| e.path.ends_with("SYSTEM"))
        .unwrap();
    // Independently computed: `printf 'regf' | shasum -a 256`.
    assert_eq!(
        system.sha256,
        "7323e77d1f51ee69b36ef874d2ee6f85f322e12a46f6281f9bd29c8dbb829460"
    );
    assert_eq!(
        system
            .host_path
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some(r"C:\Windows\System32\config\SYSTEM")
    );
}
