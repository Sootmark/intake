//! The collector's own record of a collection: KAPE console and copy logs,
//! Velociraptor collection context, log and uploads. Fixtures are built by
//! `make-kape.py` and `make-velociraptor-fs02.py`.

use std::fs;
use std::path::{Path, PathBuf};

use adapters::evtx::EvtxAdapter;
use sootmark_intake::{
    check_hashes, preview, CollectionLog, Credentials, LayoutKind, Outcome, Preview,
};

mod support;
use support::TempDir;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn preview_of(path: &Path) -> Preview {
    preview(path, &[&EvtxAdapter], &Credentials::default()).unwrap()
}

fn log_of(path: &Path) -> CollectionLog {
    preview_of(path).collection_log.expect("a collection log")
}

fn copy_dir(from: &Path, to: &Path) {
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            fs::create_dir_all(&target).unwrap();
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn kape_failures_are_read_from_the_console_log() {
    let log = log_of(&fixture("kape-fs03"));
    assert_eq!(log.collector, LayoutKind::Kape);
    assert_eq!(log.outcome, Outcome::Completed);
    assert_eq!(
        log.started.and_then(|t| t.to_iso8601()).as_deref(),
        Some("2025-08-25T20:20:59.5246365Z"),
        "the UTC run time from the file names"
    );
    assert_eq!(
        log.requested,
        [
            "EventLogs",
            "RegistryHives",
            "$J",
            "EdgeChromium",
            "Prefetch"
        ]
    );
    assert_eq!(log.failed.len(), 1);
    assert_eq!(
        log.failed[0].item,
        r"C:\Users\steven\AppData\Local\Microsoft\Edge\User Data\Default\Preferences"
    );
    assert_eq!(
        log.failed[0].reason,
        "Attempt to get an MFT record with an old reference"
    );
    assert_eq!(
        log.without_results,
        [r"C:\Windows\prefetch\BACKGROUNDTASKHOST.EXE-4210C92D.pf"],
        "gone by copy time: absent, not failed"
    );
    assert_eq!(log.error_count, 1, "'already processed' is not an error");
    assert_eq!(
        log.errors[0].time.and_then(|t| t.to_iso8601()).as_deref(),
        Some("2025-08-25T13:21:07.2124525"),
        "console times are local, zone unknown: no Z"
    );
    assert_eq!(log.warning_count, 4);
    assert_eq!(log.files_recorded, 3);
    assert_eq!(log.hashes.len(), 3);
    assert!(log.gaps.is_empty(), "totals add up: {:?}", log.gaps);
}

#[test]
fn kape_copies_match_their_recorded_sha1() {
    let source = sootmark_intake::open(&fixture("kape-fs03"), &Credentials::default()).unwrap();
    let preview = preview_of(&fixture("kape-fs03"));
    let log = preview.collection_log.as_ref().unwrap();
    assert!(
        log.hashes.iter().any(|h| h.path == "C/$Extend/$J"),
        "$UsnJrnl:$J is stored as $J"
    );
    let check = check_hashes(source.as_ref(), &preview.layout, log).unwrap();
    assert_eq!(check.checked, 3);
    assert!(check.passed(), "{check:?}");
}

#[test]
fn an_altered_or_missing_copy_is_reported() {
    let dir = TempDir::new().unwrap();
    copy_dir(&fixture("kape-fs03"), dir.path());
    fs::write(
        dir.path().join("C/Windows/System32/config/SYSTEM"),
        b"tampered",
    )
    .unwrap();
    fs::remove_file(dir.path().join("C/$Extend/$J")).unwrap();
    let source = sootmark_intake::open(dir.path(), &Credentials::default()).unwrap();
    let preview = preview_of(dir.path());
    let check = check_hashes(
        source.as_ref(),
        &preview.layout,
        preview.collection_log.as_ref().unwrap(),
    )
    .unwrap();
    assert_eq!(check.mismatched.len(), 1);
    assert_eq!(check.mismatched[0].path, "C/Windows/System32/config/SYSTEM");
    assert_eq!(check.missing, ["C/$Extend/$J"]);
    assert!(!check.passed());
}

#[test]
fn without_the_console_log_the_gap_is_stated() {
    // As inside a KAPE zip or VHDX: the console log stays outside.
    let dir = TempDir::new().unwrap();
    copy_dir(&fixture("kape-fs03"), dir.path());
    fs::remove_file(
        dir.path()
            .join("2025-08-25T20_20_59_5246365_ConsoleLog.txt"),
    )
    .unwrap();
    let log = log_of(dir.path());
    assert!(log.failed.is_empty());
    assert_eq!(log.outcome, Outcome::Unknown);
    assert!(
        log.gaps[0].contains("copy failures only there"),
        "{:?}",
        log.gaps
    );
    assert_eq!(log.hashes.len(), 3, "the CopyLog still gives hashes");
}

#[test]
fn unaccounted_files_are_flagged() {
    let dir = TempDir::new().unwrap();
    copy_dir(&fixture("kape-fs03"), dir.path());
    let console = dir
        .path()
        .join("2025-08-25T20_20_59_5246365_ConsoleLog.txt");
    let text = fs::read_to_string(&console)
        .unwrap()
        .replace("out of 6 files", "out of 9 files");
    fs::write(&console, text).unwrap();
    let log = log_of(dir.path());
    assert!(
        log.gaps.iter().any(|g| g.starts_with("3 of 9 files found")),
        "{:?}",
        log.gaps
    );
}

#[test]
fn kape_1_2_logs_are_read_too() {
    let log = log_of(&fixture("kape-ws12"));
    assert_eq!(log.version.as_deref(), Some("1.2.0.0"));
    assert_eq!(log.outcome, Outcome::Completed);
    assert_eq!(
        log.error_count, 0,
        "NLog's F level on the timing line is not an error"
    );
    assert_eq!(log.requested, ["RegistryHivesUser"]);
    assert_eq!(
        log.started.and_then(|t| t.to_iso8601()).as_deref(),
        Some("2022-05-28T02:43:44.0000000Z")
    );
    assert!(log.gaps.is_empty(), "{:?}", log.gaps);
}

#[test]
fn velociraptor_failures_and_empty_artifacts_are_told_apart() {
    let log = log_of(&fixture("Collection-FS02.zip"));
    assert_eq!(log.collector, LayoutKind::Velociraptor);
    assert_eq!(log.version.as_deref(), Some("0.7.1"));
    assert_eq!(log.outcome, Outcome::Completed);
    assert_eq!(
        log.started.and_then(|t| t.to_iso8601()).as_deref(),
        Some("2026-09-28T11:25:00.0000000Z")
    );
    assert_eq!(log.requested.len(), 4);
    assert_eq!(log.failed.len(), 1);
    assert_eq!(log.failed[0].item, "Windows.Forensics.SRUM");
    assert!(log.failed[0]
        .reason
        .contains("being used by another process"));
    assert_eq!(
        log.without_results,
        ["Windows.Registry.RDP"],
        "ran and found nothing: absent, not failed"
    );
    assert_eq!(log.error_count, 2);
    assert_eq!(log.warning_count, 1);
    assert_eq!(log.files_recorded, 3, "the sparse index row is not a file");
    assert_eq!(
        log.partial.len(),
        1,
        "sparse $J is complete; pagefile is not"
    );
    assert_eq!(log.partial[0].path, "uploads/auto/C:/pagefile.sys");
    assert!(log.gaps.is_empty(), "{:?}", log.gaps);
}

#[test]
fn a_bare_collection_has_a_log_with_nothing_to_report() {
    // FS01 carries an empty collection_context.json and no log.json.
    let log = log_of(&fixture("Collection-FS01.zip"));
    assert_eq!(log.outcome, Outcome::Unknown);
    assert!(log.failed.is_empty());
}

#[test]
fn preview_json_carries_the_collection_log() {
    let json = preview_of(&fixture("kape-fs03")).to_json();
    let log = json.get("collection_log").unwrap();
    assert_eq!(
        log.get("collector").and_then(common::json::Json::as_str),
        Some("kape")
    );
    assert_eq!(
        log.get("recorded_hashes")
            .and_then(common::json::Json::as_u64),
        Some(3)
    );
    let loose = preview_of(&fixture("kape-fs03/C")).to_json();
    assert_eq!(loose.get("collection_log"), Some(&common::json::Json::Null));
}
