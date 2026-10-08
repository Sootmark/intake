# intake

Evidence intake: directories, zips (encrypted Velociraptor collections included), tar archives (gzipped or not) and disk images; KAPE, Velociraptor, acquire and UAC layouts; detection preview.

```toml
[dependencies]
sootmark-intake = "0.12"
```

Point it at a directory, a zip, a tar archive (`.tar`, `.tar.gz`, `.tgz`: ustar, GNU long names, pax; a gzipped tar is decompressed once to a temporary file every process reuses), a disk image (E01 including split segments, VHDX, raw/split dd), an AD1 logical image (FTK Imager custom content, all segments) or a single file. It lists files, recognises the collector's layout to recover host paths (`C:\\Windows\\…`, including Velociraptor's URL-encoded and raw-device paths, acquire's `fs/C:/…` and older `sysvol/…`, UAC's `[root]/…` as Unix paths `/etc/…`, and the Sootmark collector's `C/…` with alternate data streams as `name%3Astream`), proposes a host name (the collector's own record when there is one, else the wrapping folder or the folder or archive's own name: `web1/`, `web1.zip`; never a file system's folder like `var`), and asks every adapter which files it can read, without parsing. A file that can't be read (an encrypted NTFS stream, damage) is kept in the preview with why, never fatal to the rest. A Sootmark collector archive encrypted to the case (age, `.zip.age`) is read in place with the case's identity (`Credentials::age_identities`): each chunk is decrypted as it is reached, and no plaintext is written out. For a Sootmark collector archive it reads `outcome.json` (version, host, start) and `manifest.jsonl`: what each rule collected, files cut at their limit, files that couldn't be read or weren't reached before the deadline, rules that found nothing, and every stored file's SHA-256, checked against the copy. When the collection holds a volume's `$MFT` (KAPE, Velociraptor, acquire), every collected file of that volume gets its modification time on the host from it (`Detected::ntfs_modified`), rather than the time the copy or the zip recorded. It also builds a SHA-256 manifest (zip entries are CRC-32 verified as they are hashed). Disk images are read in place, never extracted: every NTFS, FAT and exFAT volume's files (NTFS alternate data streams included) are listed, and each NTFS folder's index once it outgrew its MFT record (`$INDEX_ALLOCATION:$I30`, as `C/Users/alice/$I30`, the way KAPE and Velociraptor collect it, so the `$I30` parser finds it; the root's is `C/$I30`), the Windows volume as `C/…` and other volumes as `vol<slot>/…` (drive letters aren't stored on disk, so none is guessed). Each NTFS volume's Volume Shadow Copies (read with `sootmark-vss`) are volumes too: a snapshot's files are under `vss<n>/` and the live volume's path, the oldest snapshot being `vss1` as libvshadow and dfVFS number them (`vss1/C/Windows/System32/config/SYSTEM` is the System hive as the oldest snapshot kept it). Their host path is the live file's (`C:\\Windows\\System32\\config\\SYSTEM`), so parsers recognise them alike, and `HostPath::shadow_copy` says which snapshot they are in; the live volume's paths don't change. Each snapshot's view is built once, over one disk shared by every volume. All snapshots are read by default; `Options::shadow_copy_limit` (`open_with`, `preview_with`) keeps only the newest few, or none. The container lists every snapshot found (volume, index, creation time, store GUID, entries read), and a shadow copy that can't be read is a warning, never fatal to the image. AD1 images are read in place too: the source holding `Windows` is `C/…`, others `vol<n>/…`, FTK's file slack pseudo-files left out. The preview reports the container: format, media size, hashes and case metadata recorded at acquisition (E01), and warnings such as a VHDX not closed cleanly or an unreadable volume.

**The collector's own record** is read into a `CollectionLog`, because failures leave no files behind. Coverage needs to tell *not collected* apart from *absent*:
- **KAPE**: the ConsoleLog is the only place copy failures are recorded ("Could not copy file …"). Both console formats are read: NLog up to 1.2, Serilog from 1.3. Files gone by copy time count as absent, and the benign "already processed" error isn't counted. The console's totals are checked: copied + deduplicated + failed + missing must equal the files found. The CopyLog's SHA-1s let `check_hashes` verify every stored copy. Without the ConsoleLog (it's kept outside KAPE's zip and VHDX containers), the record says so rather than implying nothing failed.
- **Velociraptor**: `collection_context.json` (the outcome, and each artifact's status: failed with its error, or ran with no results), `log.json` (error and warning lines), `uploads.json` (files stored short of their size, told apart from sparse files) and `client_info.json` (the version).

**Encrypted collections** open in place, never decrypted to disk:
- Velociraptor **X509** collections (a random password wrapped with RSA-OAEP/SHA-512 in `metadata.json`): pass the private key, as a PEM file or simply the server's `server.config.yaml`, where every private key is tried;
- Velociraptor **Password** collections and any WinZip-AES zip (e.g. a KAPE output zipped with 7-Zip): pass the password;
- PGP collections are reported as not supported yet.

Without the credentials it needs, opening fails with a `Locked` error naming the scheme, so a UI knows what to ask for. `Credentials` never prints its secrets, even in debug output.

Written from scratch on Sootmark crates (`common`, `model`, `zip`, `disk`, `vhdx`, `ewf`, `vss`). Cryptography is not written in-house (decision D11): RustCrypto's `rsa`, `sha2` and `base64ct` (MIT OR Apache-2.0). `rsa` carries advisory RUSTSEC-2023-0071 (Marvin, a timing side channel, unpatched upstream); it needs an attacker timing many decryptions, and intake decrypts one password once, locally, so it is accepted in `deny.toml` with that reason.

## Quality

`#![forbid(unsafe_code)]`, `clippy::pedantic` clean, `cargo-deny` (permissive licences, no network crates).

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
