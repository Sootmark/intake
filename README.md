# intake

Evidence intake: directories, zips (encrypted Velociraptor collections included) and disk images, KAPE and Velociraptor layouts, detection preview.

```toml
[dependencies]
sootmark-intake = "0.2"
```

Point it at a directory, a zip, a disk image (E01 including split segments, VHDX, raw/split dd), an AD1 logical image (FTK Imager custom content, all segments) or a single file. It lists files, recognises the collector's layout to recover host paths (`C:\\Windows\\…`, including Velociraptor's URL-encoded and raw-device paths), proposes a host name, and asks every adapter which files it can read, without parsing. A file that can't be read (an encrypted NTFS stream, damage) is kept in the preview with why, never fatal to the rest. It also builds a SHA-256 manifest (zip entries are CRC-32 verified as they are hashed). Disk images are read in place, never extracted: every NTFS, FAT and exFAT volume's files (NTFS alternate data streams included) are listed, the Windows volume as `C/…` and other volumes as `vol<slot>/…` (drive letters aren't stored on disk, so none is guessed). AD1 images are read in place too: the source holding `Windows` is `C/…`, others `vol<n>/…`, FTK's file slack pseudo-files left out. The preview reports the container: format, media size, hashes and case metadata recorded at acquisition (E01), and warnings such as a VHDX not closed cleanly or an unreadable volume.

**The collector's own record** is read into a `CollectionLog`, because failures leave no files behind. Coverage needs to tell *not collected* apart from *absent*:
- **KAPE**: the ConsoleLog is the only place copy failures are recorded ("Could not copy file …"). Both console formats are read: NLog up to 1.2, Serilog from 1.3. Files gone by copy time count as absent, and the benign "already processed" error isn't counted. The console's totals are checked: copied + deduplicated + failed + missing must equal the files found. The CopyLog's SHA-1s let `check_hashes` verify every stored copy. Without the ConsoleLog (it's kept outside KAPE's zip and VHDX containers), the record says so rather than implying nothing failed.
- **Velociraptor**: `collection_context.json` (the outcome, and each artifact's status: failed with its error, or ran with no results), `log.json` (error and warning lines), `uploads.json` (files stored short of their size, told apart from sparse files) and `client_info.json` (the version).

**Encrypted collections** open in place, never decrypted to disk:
- Velociraptor **X509** collections (a random password wrapped with RSA-OAEP/SHA-512 in `metadata.json`): pass the private key, as a PEM file or simply the server's `server.config.yaml`, where every private key is tried;
- Velociraptor **Password** collections and any WinZip-AES zip (e.g. a KAPE output zipped with 7-Zip): pass the password;
- PGP collections are reported as not supported yet.

Without the credentials it needs, opening fails with a `Locked` error naming the scheme, so a UI knows what to ask for. `Credentials` never prints its secrets, even in debug output.

Written from scratch on Sootmark crates (`common`, `model`, `zip`, `disk`, `vhdx`, `ewf`). Cryptography is not written in-house (decision D11): RustCrypto's `rsa`, `sha2` and `base64ct` (MIT OR Apache-2.0). `rsa` carries advisory RUSTSEC-2023-0071 (Marvin, a timing side channel, unpatched upstream); it needs an attacker timing many decryptions, and intake decrypts one password once, locally, so it is accepted in `deny.toml` with that reason.

## Quality

`#![forbid(unsafe_code)]`, `clippy::pedantic` clean, `cargo-deny` (permissive licences, no network crates).

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
