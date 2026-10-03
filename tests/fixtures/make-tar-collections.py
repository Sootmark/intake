#!/usr/bin/env python3
"""Build the tar collections for tests/tar.rs (synthetic, deterministic).

tar/acquire-ws01.tar.gz  acquire layout (fs/C:/...), pax format: a path
                         longer than 100 bytes, a directory and a symlink
                         (not files), a file written twice (the later wins).
tar/acquire-old.tar      older acquire layout (sysvol/...), GNU format with
                         a long name, uncompressed.
tar/uac-srv-web01.tar.gz UAC layout: [root]/..., live_response/, uac.log,
                         gzip with a file name in its header.
tar/damaged.tar          a header whose checksum doesn't match.
"""

import gzip
import io
import tarfile
from pathlib import Path

HERE = Path(__file__).parent / "tar"
EVTX = b"ElfFile\0 rest of the header"
LONG = "fs/C:/Users/alice/AppData/Local/Microsoft/Windows/PowerShell/PSReadLine/" + "very-long-folder-name/" * 3 + "ConsoleHost_history.txt"


def add(tar, name, data=b"", kind=tarfile.REGTYPE, target=""):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.size = len(data) if kind == tarfile.REGTYPE else 0
    info.mtime = 1_790_000_000
    info.linkname = target
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)


def tar_bytes(fmt, entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=fmt) as tar:
        for entry in entries:
            add(tar, *entry)
    return buffer.getvalue()


def gz(data, name=""):
    out = io.BytesIO()
    with gzip.GzipFile(filename=name, mode="wb", fileobj=out, mtime=1_790_000_000) as f:
        f.write(data)
    return out.getvalue()


HERE.mkdir(exist_ok=True)
(HERE / "acquire-ws01.tar.gz").write_bytes(gz(tar_bytes(tarfile.PAX_FORMAT, [
    ("fs/C:/Windows/System32/winevt/Logs/Security.evtx", EVTX),
    ("fs/C:/Windows/System32/config/SYSTEM", b"regf old"),
    ("fs/C:/Windows/System32/config/SYSTEM", b"regf"),
    ("fs/C:/Windows/Temp", b"", tarfile.DIRTYPE),
    ("fs/C:/Windows/link.evtx", b"", tarfile.SYMTYPE, "System32/winevt/Logs/Security.evtx"),
    (LONG, b"whoami\n"),
])))
(HERE / "acquire-old.tar").write_bytes(tar_bytes(tarfile.GNU_FORMAT, [
    ("sysvol/Windows/System32/winevt/Logs/System.evtx", EVTX),
    ("sysvol/Users/bob/" + "deep/" * 25 + "notes.txt", b"note"),
]))
(HERE / "uac-srv-web01.tar.gz").write_bytes(gz(tar_bytes(tarfile.USTAR_FORMAT, [
    ("[root]/etc/passwd", b"root:x:0:0:root:/root:/bin/bash\n"),
    ("[root]/var/log/auth.log", b"Oct  3 10:00:00 srv-web01 sshd[1]: Accepted password for root\n"),
    ("live_response/system/hostname.txt", b"srv-web01\n"),
    ("uac.log", b"2026-10-03 10:00:00 INF UAC (Unix-like Artifacts Collector) 3.4.0\n"),
]), name="uac-srv-web01.tar"))
damaged = bytearray(tar_bytes(tarfile.USTAR_FORMAT, [("a.txt", b"a"), ("b.txt", b"b")]))
damaged[512 * 2 + 10] ^= 0xFF  # the second header's name
(HERE / "damaged.tar").write_bytes(bytes(damaged))
