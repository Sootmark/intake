//! Encrypted collections, laid out as Velociraptor writes them: an outer
//! zip with a WinZip-AES `data.zip` (the real collection) and, for X509, a
//! `metadata.json` holding the password wrapped with RSA-OAEP (SHA-512).
//! Built with 7-Zip and OpenSSL (see `fixtures/keys/README.md`); the inner
//! collection is `Collection-FS01.zip`.

use std::io;
use std::path::{Path, PathBuf};

use adapters::evtx::EvtxAdapter;
use sootmark_intake::{preview, Credentials, HintSource, LayoutKind, Locked, Preview, Scheme};

mod support;
use support::TempDir;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn key(name: &str) -> Credentials {
    Credentials {
        private_keys: Some(std::fs::read_to_string(fixture(&format!("keys/{name}"))).unwrap()),
        ..Credentials::default()
    }
}

fn password(password: &str) -> Credentials {
    Credentials {
        password: Some(password.to_owned()),
        ..Credentials::default()
    }
}

fn open(name: &str, credentials: &Credentials) -> io::Result<Preview> {
    preview(&fixture(name), &[&EvtxAdapter], credentials)
}

/// What `Collection-FS01.zip` holds, whichever way it was protected.
fn assert_is_fs01(preview: &Preview) {
    assert_eq!(preview.layout.kind, LayoutKind::Velociraptor);
    let hint = preview.layout.host_hint.as_ref().unwrap();
    assert_eq!(
        (hint.name.as_str(), hint.source),
        ("FS01", HintSource::CollectorMetadata)
    );
    assert_eq!(preview.by_parser["evtx"].files, 1);
    let plain = open("Collection-FS01.zip", &Credentials::default()).unwrap();
    assert_eq!(preview.total, plain.total);
}

#[test]
#[cfg(feature = "x509")]
fn x509_collections_open_with_the_private_key() {
    for key_file in ["frontend.key", "frontend-pkcs8.key"] {
        let preview = open("collection-x509.zip", &key(key_file)).unwrap();
        assert_eq!(preview.protection, Some(Scheme::X509), "{key_file}");
        assert_is_fs01(&preview);
    }
}

#[test]
#[cfg(feature = "x509")]
fn the_server_config_works_as_the_key_file() {
    // It holds the CA key first, then the frontend key the collection needs.
    let preview = open("collection-x509.zip", &key("server.config.yaml")).unwrap();
    assert_is_fs01(&preview);
}

#[test]
#[cfg(feature = "x509")]
fn the_wrong_key_is_refused() {
    let error = open("collection-x509.zip", &key("ca.key")).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(
        Locked::of(&error),
        None,
        "a key was given: not merely locked"
    );
}

#[test]
fn password_collections_open_with_the_password() {
    let preview = open("collection-password.zip", &password("velociraptor-test")).unwrap();
    assert_eq!(preview.protection, Some(Scheme::Password));
    assert_is_fs01(&preview);
    let wrong = open("collection-password.zip", &password("guess")).unwrap_err();
    assert_eq!(wrong.kind(), io::ErrorKind::PermissionDenied);
}

#[test]
fn missing_credentials_say_what_is_needed() {
    for (name, scheme) in [
        #[cfg(feature = "x509")]
        ("collection-x509.zip", Scheme::X509),
        ("collection-password.zip", Scheme::Password),
        ("kape-password.zip", Scheme::Password),
    ] {
        let error = open(name, &Credentials::default()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{name}");
        assert_eq!(Locked::of(&error), Some(Locked { scheme }), "{name}");
    }
}

#[test]
fn pgp_collections_are_reported_unsupported() {
    let error = open("collection-pgp.zip", &key("frontend.key")).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert_eq!(Locked::of(&error).map(|l| l.scheme), Some(Scheme::Pgp));
}

#[test]
fn password_protected_kape_zips_open_too() {
    let preview = open("kape-password.zip", &password("kape-test")).unwrap();
    assert_eq!(preview.protection, Some(Scheme::Password));
    assert_eq!(preview.layout.kind, LayoutKind::Kape);
    assert_eq!(preview.by_parser["evtx"].files, 1);
    let wrong = open("kape-password.zip", &password("guess")).unwrap_err();
    assert_eq!(wrong.kind(), io::ErrorKind::PermissionDenied);
}

#[test]
#[cfg(feature = "x509")]
fn preview_json_names_the_encryption() {
    let json = open("collection-x509.zip", &key("frontend.key"))
        .unwrap()
        .to_json();
    assert_eq!(
        json.get("encryption").and_then(common::json::Json::as_str),
        Some("x509")
    );
}

/// A Sootmark collector archive, as the collector writes it, encrypted to
/// `recipient` with age.
fn age_archive(dir: &Path, recipient: age::Recipient) -> std::path::PathBuf {
    let mut zip = zip::Writer::new(Vec::new());
    zip.add(
        "C/Users/a/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
        None,
        &mut b"whoami\n".as_slice(),
    )
    .unwrap();
    zip.add("manifest.jsonl", None, &mut b"".as_slice())
        .unwrap();
    zip.add(
        "outcome.json",
        None,
        &mut br#"{"collector":"sootmark-collector","version":"0.2.0","host":"WS-042"}"#.as_slice(),
    )
    .unwrap();
    let mut encryptor = age::Encryptor::new(Vec::new(), &[recipient]).unwrap();
    std::io::Write::write_all(&mut encryptor, &zip.finish().unwrap()).unwrap();
    let path = dir.join("WS-042.zip.age");
    std::fs::write(&path, encryptor.finish().unwrap()).unwrap();
    path
}

#[test]
fn age_encrypted_archives_open_with_their_key() {
    let dir = TempDir::new().unwrap();
    let identity = age::Identity::generate();
    let path = age_archive(dir.path(), identity.to_public());
    let with = |identities: Option<String>| Credentials {
        age_identities: identities,
        ..Credentials::default()
    };

    let preview = preview(&path, &[&EvtxAdapter], &with(Some(identity.to_string()))).unwrap();
    assert_eq!(preview.protection, Some(Scheme::Age));
    assert_eq!(preview.layout.kind, LayoutKind::Sootmark);
    assert_eq!(preview.layout.host_hint.unwrap().name, "WS-042");
    assert!(preview
        .files
        .iter()
        .any(|f| f.path.ends_with("ConsoleHost_history.txt")));

    let locked = preview_error(&path, &with(None));
    assert_eq!(Locked::of(&locked).map(|l| l.scheme), Some(Scheme::Age));
    let stranger = age::Identity::generate().to_string();
    let refused = preview_error(&path, &with(Some(stranger)));
    assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
}

fn preview_error(path: &Path, credentials: &Credentials) -> std::io::Error {
    match preview(path, &[&EvtxAdapter], credentials) {
        Ok(_) => panic!("opened without the right key"),
        Err(error) => error,
    }
}
