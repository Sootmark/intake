//! Intake on disk images of FIN-WKS-07 (GPT: MSR, NTFS, FAT32), the same
//! disk as raw, VHDX and E01. Expected contents come from The Sleuth Kit
//! (`fls`, `icat`) and the stored hashes from `ewfinfo`.

use std::fs;
use std::path::{Path, PathBuf};

use adapters::evtx::EvtxAdapter;
use sootmark_intake::{open, preview, ContainerFormat, Credentials, LayoutKind, Preview};

mod support;
use support::TempDir;

/// `icat -o 256 fin-wks-07.img 34 | shasum -a 256`
const RCLONE_CONF_SHA256: &str = "8c4dc8c2ac27226bb585cff90ecec13394bd51e792296d1333ef178df5a2f57f";
/// `icat -o 256 fin-wks-07.img 23-128-3 | shasum -a 256`
const ZONE_IDENTIFIER_SHA256: &str =
    "ca9dfb47c66ad01c49bf8f5841d734da9e5828a6c11a6a5bc0b726bf21e1973a";
const RCLONE_CONF: &str = "vol1/Users/svc_backup/AppData/Roaming/rclone/rclone.conf";
const ZONE_IDENTIFIER: &str = "vol1/Users/svc_backup/Downloads/tools.zip:Zone.Identifier";
/// The FAT32 `E:` volume's files, as `tests/fixtures/make-samples.py` in
/// `sootmark-disk` writes them (a small FAT32 The Sleuth Kit doesn't
/// read; `sootmark-disk` checks FAT against it on other volumes).
const FAT_FILES: [&str; 4] = [
    "vol2/System Volume Information/IndexerVolumeGuid",
    "vol2/exfil/Q3_forecast_board_pack.zip",
    "vol2/exfil/payroll_2026-08.csv",
    "vol2/exfil/vendor_master.csv",
];
/// SHA-256 of the generator's `PAYROLL` content.
const PAYROLL_SHA256: &str = "ed84d3f9d569e907de906f59b1514fe55fd3475b10a22f081fad2579c1037727";
const IMAGES: [&str; 4] = [
    "fin-wks-07.img",
    "fin-wks-07-dynamic.vhdx",
    "encase6-best.E01",
    "encase6-split.E01",
];

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn preview_of(path: &Path) -> Preview {
    preview(path, &[&EvtxAdapter], &Credentials::default()).unwrap()
}

fn sha256_of(path: &Path, stored: &str) -> String {
    let source = open(path, &Credentials::default()).unwrap();
    let entry = source
        .entries()
        .unwrap()
        .into_iter()
        .find(|e| e.path == stored)
        .unwrap_or_else(|| panic!("{stored} not listed"));
    common::hex::encode(&source.sha256(&entry).unwrap())
}

#[test]
fn every_container_yields_the_same_volume() {
    for image in IMAGES {
        let preview = preview_of(&fixture(image));
        let container = preview.container.as_ref().expect("a container");
        assert_eq!(container.media_size, 1_802_240, "{image}");
        assert_eq!(preview.layout.kind, LayoutKind::DiskImage, "{image}");
        assert_eq!(preview.total.files, 21, "{image}");
        assert!(
            container.warnings.is_empty(),
            "{image}: {:?}",
            container.warnings
        );
        let fat: Vec<&str> = preview
            .files
            .iter()
            .map(|f| f.path.as_str())
            .filter(|p| p.starts_with("vol2/"))
            .collect();
        assert_eq!(fat, FAT_FILES, "{image}: the FAT32 volume's files");
        assert_eq!(
            sha256_of(&fixture(image), FAT_FILES[2]),
            PAYROLL_SHA256,
            "{image}"
        );
        assert_eq!(
            sha256_of(&fixture(image), RCLONE_CONF),
            RCLONE_CONF_SHA256,
            "{image}"
        );
        assert_eq!(
            sha256_of(&fixture(image), ZONE_IDENTIFIER),
            ZONE_IDENTIFIER_SHA256,
            "{image}"
        );
    }
}

#[test]
fn volumes_without_windows_get_no_drive_letter() {
    let preview = preview_of(&fixture("fin-wks-07.img"));
    let rclone = preview
        .files
        .iter()
        .find(|f| f.path == RCLONE_CONF)
        .unwrap();
    let host_path = rclone.host_path.as_ref().unwrap();
    assert_eq!(host_path.drive(), None);
    assert_eq!(
        host_path.to_string(),
        r"\Users\svc_backup\AppData\Roaming\rclone\rclone.conf"
    );
}

#[test]
fn reports_the_container_format() {
    let format = |image| preview_of(&fixture(image)).container.unwrap().format;
    assert_eq!(format("fin-wks-07.img"), ContainerFormat::Raw);
    assert_eq!(format("fin-wks-07-dynamic.vhdx"), ContainerFormat::Vhdx);
    assert_eq!(format("encase6-best.E01"), ContainerFormat::E01);
}

#[test]
fn e01_carries_acquisition_hashes_and_case_metadata() {
    let container = preview_of(&fixture("encase6-best.E01")).container.unwrap();
    assert_eq!(
        container.stored_md5.as_deref(),
        Some("7051d0bae80b472da82c8ff0b96a7738")
    );
    assert_eq!(
        container.stored_sha1.as_deref(),
        Some("13ebfae8afac9c2ae214fcaf9c0772f9c1489d94")
    );
    let field = |name| {
        container
            .acquisition
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    };
    assert_eq!(field("case_number"), Some("FIN-2026-001"));
    assert_eq!(field("description"), Some("FIN-WKS-07"));
    assert_eq!(field("examiner"), Some("Sootmark"));
}

#[test]
fn preview_json_includes_the_container() {
    let json = preview_of(&fixture("encase6-best.E01")).to_json();
    let container = json.get("container").unwrap();
    assert_eq!(
        container.get("format").and_then(common::json::Json::as_str),
        Some("e01")
    );
    let folder = preview_of(&fixture("Collection-FS01.zip")).to_json();
    assert_eq!(folder.get("container"), Some(&common::json::Json::Null));
}

#[test]
fn an_image_without_a_file_system_says_so() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("blank.img");
    fs::write(&path, vec![0u8; 64 * 1024]).unwrap();
    let preview = preview_of(&path);
    assert_eq!(preview.total.files, 0);
    assert_eq!(
        preview.container.unwrap().warnings,
        ["no readable NTFS, FAT or exFAT volume in the image"]
    );
}

#[test]
fn a_damaged_e01_is_an_error_not_a_panic() {
    let dir = TempDir::new().unwrap();
    let original = fs::read(fixture("encase6-best.E01")).unwrap();
    for cut in [8, 13, 100, original.len() / 2] {
        let path = dir.path().join("cut.E01");
        fs::write(&path, &original[..cut]).unwrap();
        assert!(
            preview(&path, &[&EvtxAdapter], &Credentials::default()).is_err(),
            "cut at {cut}"
        );
    }
}

#[test]
fn a_split_e01_missing_a_segment_is_an_error() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("split.E01");
    fs::copy(fixture("encase6-split.E01"), &path).unwrap();
    assert!(preview(&path, &[&EvtxAdapter], &Credentials::default()).is_err());
}

#[test]
fn corrupted_images_never_panic() {
    let dir = TempDir::new().unwrap();
    let original = fs::read(fixture("fin-wks-07.img")).unwrap();
    // Deterministic corruption across the GPT, boot sector, $MFT and data.
    let mut state: u32 = 0x5eed;
    for round in 0..64 {
        let mut damaged = original.clone();
        for _ in 0..32 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let at = (state as usize >> 4) % (256 * 1024 + 64 * 1024);
            damaged[at] ^= (state >> 24) as u8 | 1;
        }
        let path = dir.path().join(format!("damaged-{round}.img"));
        fs::write(&path, &damaged).unwrap();
        // Either outcome is fine; panicking or hanging is not.
        let _ = preview(&path, &[&EvtxAdapter], &Credentials::default());
    }
}
