//! Unwrapping the password of X509-encrypted Velociraptor collections:
//! RSA-OAEP with SHA-512, as Velociraptor's `pk_encrypt` does.
//!
//! RSA comes from RustCrypto's `rsa` (decision D11): cryptography is not
//! written in-house. Behind the `x509` feature (on by default), so builds
//! that don't need it, such as wasm32, avoid `rsa` and its randomness
//! dependencies.

use std::io;

use base64ct::{Base64, Encoding};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Oaep, RsaPrivateKey};
use sha2::Sha512;

use crate::protected::invalid;

const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_END: &str = "-----END ";
const PEM_PKCS1: &str = "RSA PRIVATE KEY";
const PEM_PKCS8: &str = "PRIVATE KEY";

/// Decrypt the base64 RSA-OAEP (SHA-512) `wrapped` password with the first
/// key in `keys` that can.
pub(crate) fn unwrap_password(keys: &str, wrapped: &str) -> io::Result<Vec<u8>> {
    let ciphertext =
        Base64::decode_vec(wrapped.trim()).map_err(|_| invalid("EncryptedPass is not base64"))?;
    let candidates = private_keys(keys);
    if candidates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no unencrypted RSA private key (PEM) found in the key file",
        ));
    }
    candidates
        .iter()
        .find_map(|key| key.decrypt(Oaep::new::<Sha512>(), &ciphertext).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "none of the private keys given opens this collection",
            )
        })
}

/// Every RSA private key in PEM form in `text`, wherever it sits: a key
/// file, or a YAML block scalar (indented lines) as in `server.config.yaml`.
fn private_keys(text: &str) -> Vec<RsaPrivateKey> {
    let mut keys = Vec::new();
    let mut block: Option<(String, String)> = None;
    for line in text.lines().map(str::trim) {
        if let Some(label) = pem_label(line, PEM_BEGIN) {
            block = Some((label.to_owned(), format!("{line}\n")));
        } else if let Some((label, pem)) = &mut block {
            pem.push_str(line);
            pem.push('\n');
            if pem_label(line, PEM_END) == Some(label.as_str()) {
                keys.extend(parse_key(label, pem));
                block = None;
            }
        }
    }
    keys
}

/// `RSA PRIVATE KEY` from `-----BEGIN RSA PRIVATE KEY-----`.
fn pem_label<'l>(line: &'l str, marker: &str) -> Option<&'l str> {
    line.strip_prefix(marker)?.strip_suffix("-----")
}

fn parse_key(label: &str, pem: &str) -> Option<RsaPrivateKey> {
    match label {
        PEM_PKCS1 => RsaPrivateKey::from_pkcs1_pem(pem).ok(),
        PEM_PKCS8 => RsaPrivateKey::from_pkcs8_pem(pem).ok(),
        // Encrypted keys, EC keys, certificates: not usable here.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_non_key_pem_blocks() {
        let text = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert!(private_keys(text).is_empty());
    }
}
