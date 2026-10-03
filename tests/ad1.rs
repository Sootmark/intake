//! Intake on an AD1 logical image (`tests/fixtures/ad1/synthetic.ad1`, a
//! Windows volume and a USB volume as FTK Imager exports them; real images
//! are checked in `sootmark-ad1`): entries under `C/` and `vol<n>/`, file
//! slack left out, content read from the image.

use std::path::Path;

use sootmark_intake::{open, ContainerFormat, Credentials};

#[test]
fn ad1_files_are_entries_under_their_volume() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ad1/synthetic.ad1");
    let source = open(&path, &Credentials::default()).unwrap();
    let paths: Vec<String> = source
        .entries()
        .unwrap()
        .into_iter()
        .map(|e| e.path)
        .collect();
    assert_eq!(
        paths,
        [
            "C/Users/alice/notes.txt",
            "C/Windows/System32/drivers/etc/hosts",
            "vol2/report.docx",
        ]
    );
    let container = source.container().unwrap();
    assert_eq!(container.format, ContainerFormat::Ad1);
    assert!(container.volume_layout);
    assert!(container.warnings.is_empty(), "{:?}", container.warnings);
    let entry = source
        .entries()
        .unwrap()
        .into_iter()
        .find(|e| e.path.ends_with("hosts"))
        .unwrap();
    let mut text = String::new();
    source
        .with_reader(&entry, &mut |r| r.read_to_string(&mut text).map(|_| ()))
        .unwrap();
    assert_eq!(text, "127.0.0.1 localhost\n");
}
