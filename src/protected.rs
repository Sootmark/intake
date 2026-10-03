//! Encrypted ("protected") Velociraptor collections.
//!
//! Zip encryption hides contents but not names, so Velociraptor puts the
//! whole collection in a stored, WinZip-AES-encrypted `data.zip` inside the
//! outer zip. The password is either chosen by the analyst (the Password
//! scheme, no metadata) or random and wrapped with RSA-OAEP (SHA-512) for a
//! certificate, stored base64-encoded as `EncryptedPass` in a plain
//! `metadata.json` (the X509 scheme; by default the certificate is the
//! server's frontend certificate, so the key is in `server.config.yaml`).
//!
//! X509 support (RSA) is the `x509` feature, on by default; see `x509.rs`.

use core::fmt;
use std::io::{self, Read, Seek};

use common::json::{self, Json};
use zip::{Archive, Encryption};

/// The encrypted inner collection.
const DATA_ZIP: &str = "data.zip";
/// Plain metadata next to it, holding the wrapped password.
const METADATA: &str = "metadata.json";
/// Upper bound on metadata read.
const METADATA_LIMIT: u64 = 1 << 20;

/// How an encrypted collection is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// A password chosen when the collector was built.
    Password,
    /// A random password wrapped with RSA for a certificate.
    X509,
    /// A random password wrapped with PGP (not supported yet).
    Pgp,
}

impl Scheme {
    /// Stable identifier used in JSON output.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::X509 => "x509",
            Self::Pgp => "pgp",
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Password => "Password",
            Self::X509 => "X509",
            Self::Pgp => "PGP",
        })
    }
}

/// What the analyst supplies to open protected collections.
#[derive(Clone, Default)]
pub struct Credentials {
    /// The collection password (Password scheme).
    pub password: Option<String>,
    /// Text holding one or more PEM private keys (X509 scheme): a key file,
    /// or Velociraptor's `server.config.yaml` as it is.
    pub private_keys: Option<String>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print secrets, not even in debug output.
        f.debug_struct("Credentials")
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field(
                "private_keys",
                &self.private_keys.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// The error when a protected collection needs credentials that weren't
/// given. Carried inside an [`io::Error`] of kind
/// [`io::ErrorKind::PermissionDenied`]; see [`Locked::of`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Locked {
    /// What the collection needs.
    pub scheme: Scheme,
}

impl Locked {
    /// The `Locked` inside `error`, if that's what it is.
    #[must_use]
    pub fn of(error: &io::Error) -> Option<Self> {
        error.get_ref()?.downcast_ref::<Self>().copied()
    }

    pub(crate) fn error(scheme: Scheme) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, Self { scheme })
    }
}

impl fmt::Display for Locked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.scheme {
            Scheme::Password => f.write_str("encrypted collection: the password is needed"),
            Scheme::X509 => f.write_str(
                "encrypted Velociraptor collection (X509): the private key is needed \
                 (a PEM key file, or the server's server.config.yaml)",
            ),
            Scheme::Pgp => {
                f.write_str("encrypted Velociraptor collection (PGP): not supported yet")
            }
        }
    }
}

impl std::error::Error for Locked {}

/// A protected collection found in an archive.
pub(crate) struct Protection {
    pub(crate) scheme: Scheme,
    /// Index of `data.zip` in the outer archive.
    pub(crate) data: usize,
    /// The wrapped password (X509), base64.
    encrypted_pass: Option<String>,
}

/// The protection of `archive`, if it's a protected collection: an
/// encrypted top-level `data.zip`, with or without `metadata.json`.
pub(crate) fn detect<R: Read + Seek>(archive: &mut Archive<R>) -> io::Result<Option<Protection>> {
    let Some(data) = archive
        .entries()
        .iter()
        .position(|e| e.name == DATA_ZIP && matches!(e.encryption, Some(Encryption::Aes(_))))
    else {
        return Ok(None);
    };
    let metadata = match archive.entries().iter().position(|e| e.name == METADATA) {
        Some(index) => Some(read_metadata(archive, index)?),
        None => None,
    };
    let row = metadata.as_ref().and_then(scheme_row);
    let scheme = match row.and_then(|r| r.get("Scheme")).and_then(Json::as_str) {
        None => Scheme::Password,
        Some(s) if s.eq_ignore_ascii_case("x509") => Scheme::X509,
        Some(s) if s.eq_ignore_ascii_case("pgp") => Scheme::Pgp,
        Some(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "encrypted Velociraptor collection with an unknown scheme",
            ))
        }
    };
    let encrypted_pass = row
        .and_then(|r| r.get("EncryptedPass"))
        .and_then(Json::as_str)
        .map(str::to_owned);
    Ok(Some(Protection {
        scheme,
        data,
        encrypted_pass,
    }))
}

fn read_metadata<R: Read + Seek>(archive: &mut Archive<R>, index: usize) -> io::Result<Json> {
    let mut text = String::new();
    archive
        .reader(index)?
        .take(METADATA_LIMIT)
        .read_to_string(&mut text)?;
    json::parse(&text).map_err(|_| invalid("unreadable metadata.json"))
}

/// The row naming the scheme: `metadata.json` holds an array of rows
/// (a single object is accepted too).
fn scheme_row(metadata: &Json) -> Option<&Json> {
    match metadata {
        Json::Array(rows) => rows.iter().find(|row| row.get("Scheme").is_some()),
        row => row.get("Scheme").map(|_| row),
    }
}

impl Protection {
    /// The password of `data.zip`.
    ///
    /// # Errors
    /// A [`Locked`] error when `credentials` lack what the scheme needs;
    /// [`io::ErrorKind::PermissionDenied`] when no given key unwraps the
    /// password.
    pub(crate) fn password(&self, credentials: &Credentials) -> io::Result<Vec<u8>> {
        match self.scheme {
            Scheme::Password => credentials
                .password
                .as_ref()
                .map(|p| p.as_bytes().to_vec())
                .ok_or_else(|| Locked::error(Scheme::Password)),
            Scheme::X509 => {
                let keys = credentials
                    .private_keys
                    .as_deref()
                    .ok_or_else(|| Locked::error(Scheme::X509))?;
                let wrapped = self
                    .encrypted_pass
                    .as_deref()
                    .ok_or_else(|| invalid("metadata.json has no EncryptedPass"))?;
                unwrap_password(keys, wrapped)
            }
            Scheme::Pgp => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                Locked {
                    scheme: Scheme::Pgp,
                },
            )),
        }
    }
}

#[cfg(feature = "x509")]
use crate::x509::unwrap_password;

#[cfg(not(feature = "x509"))]
fn unwrap_password(_keys: &str, _wrapped: &str) -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "X509-encrypted collections need the x509 feature, disabled in this build",
    ))
}

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_never_print_secrets() {
        let credentials = Credentials {
            password: Some("hunter2".to_owned()),
            private_keys: Some("-----BEGIN RSA PRIVATE KEY-----".to_owned()),
        };
        let printed = format!("{credentials:?}");
        assert!(!printed.contains("hunter2"));
        assert!(!printed.contains("BEGIN"));
    }

    #[test]
    fn finds_the_scheme_row() {
        let rows =
            json::parse(r#"[{"Other": 1}, {"Scheme": "X509", "EncryptedPass": "AA=="}]"#).unwrap();
        assert_eq!(
            scheme_row(&rows)
                .and_then(|r| r.get("Scheme"))
                .and_then(Json::as_str),
            Some("X509")
        );
        let object = json::parse(r#"{"Scheme": "pgp"}"#).unwrap();
        assert!(scheme_row(&object).is_some());
    }

    #[test]
    fn locked_errors_are_recognisable() {
        let error = Locked::error(Scheme::X509);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            Locked::of(&error),
            Some(Locked {
                scheme: Scheme::X509
            })
        );
        assert_eq!(Locked::of(&io::Error::other("x")), None);
    }
}
