#!/usr/bin/env python3
"""Build KAPE target collections for the collection-log tests.

kape-fs03/   KAPE 1.3 layout (Serilog console, `T20_20_59_5246365` names,
             `_SkipLog.csv.csv`), with one copy failure and one file gone
             by copy time.
kape-ws12/   KAPE 1.2 layout (NLog console, `T024344` names).

Line formats, columns and conventions (UTF-8 BOM, CRLF, uppercase SHA-1,
`$UsnJrnl:$J` stored as `$J`) follow KapeDocs "Log files" and real KAPE
output published on GitHub; the hosts and paths are synthetic. SHA-1s are
computed from the files written here.

    python3 make-kape.py
"""

import hashlib
import pathlib
import shutil

here = pathlib.Path(__file__).parent
BOM = "\ufeff"
EVTX = b"ElfFile\0 rest of the header"
COPY_HEADER = "CopiedTimestamp,SourceFile,DestinationFile,FileSize,SourceFileSha1,DeferredCopy,CreatedOnUtc,ModifiedOnUtc,LastAccessedOnUtc,CopyDuration"


def write(root, relative, data):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def crlf(lines):
    return "".join(line + "\r\n" for line in lines)


def copy_log(root, tdest, files):
    rows = [COPY_HEADER]
    for source, stored, data, deferred in files:
        write(root, stored, data)
        sha1 = hashlib.sha1(data).hexdigest().upper()
        destination = tdest + "\\" + stored.replace("/", "\\")
        t = "2025-08-25 20:21:09.9776063"
        rows.append(f"{t},{source},{destination},{len(data)},{sha1},{deferred},{t},{t},{t},00:00:00.0154972")
    return (BOM + crlf(rows)).encode("utf-8")


def fs03():
    root = here / "kape-fs03"
    shutil.rmtree(root, ignore_errors=True)
    run = "2025-08-25T20_20_59_5246365"
    tdest = r"C:\cases\FS03\tout"
    files = [
        (r"C:\Windows\System32\winevt\Logs\Security.evtx", "C/Windows/System32/winevt/Logs/Security.evtx", EVTX, "True"),
        (r"C:\Windows\System32\config\SYSTEM", "C/Windows/System32/config/SYSTEM", b"regf synthetic hive", "True"),
        (r"C:\$Extend\$UsnJrnl:$J", "C/$Extend/$J", b"USN records", "True"),
    ]
    write(root, f"{run}_CopyLog.csv", copy_log(root, tdest, files))
    write(root, f"{run}_SkipLog.csv.csv", (BOM + crlf([
        "SourceFile,SourceFileSha1,Reason",
        r"C:\Windows\System32\config\RegBack\SYSTEM," + hashlib.sha1(b"regf synthetic hive").hexdigest().upper() + ",Deduped",
    ])).encode("utf-8"))
    console = [
        r"[2025-08-25 13:20:59.6012345 | INF] KAPE directory: C:\Tools\KAPE",
        r"[2025-08-25 13:20:59.6023456 | INF] Command line:   --tsource C: --tdest C:\cases\FS03\tout --tflush --target EventLogs,RegistryHives,$J,EdgeChromium,Prefetch --gui",
        '[2025-08-25 13:20:59.6034567 | INF] System info: Machine name: FS03, 64-bit: true, User: Administrator OS: "Windows10" (10.0.19045)',
        "[2025-08-25 13:20:59.6045678 | INF] Using Target operations",
        r"[2025-08-25 13:20:59.6056789 | WRN]   Flushing target destination directory C:\cases\FS03\tout",
        "[2025-08-25 13:21:00.1807432 | INF] Found 5 targets. Expanding targets to file list...",
        "[2025-08-25 13:21:00.2807432 | ERR] Target RegistryHives with Id 2da16dbf-ea47-448e-a00f-fc442c3109ba already processed. Skipping!",
        "[2025-08-25 13:21:02.1807432 | INF] Found 6 files in 2.001 seconds. Beginning copy...",
        r"[2025-08-25 13:21:02.2807432 | INF]   Deferring C:\$Extend\$UsnJrnl:$J due to UnauthorizedAccessException...",
        r"[2025-08-25 13:21:03.1807432 | WRN] File C:\Windows\prefetch\BACKGROUNDTASKHOST.EXE-4210C92D.pf does not exist! Skipping!",
        "[2025-08-25 13:21:05.1807432 | INF] Deferred file count: 3. Copying locked files...",
        "[2025-08-25 13:21:06.2124525 | WRN]   Skipping sparse data area in $J!",
        r"[2025-08-25 13:21:07.2124525 | FTL] Could not copy file C:\Users\steven\AppData\Local\Microsoft\Edge\User Data\Default\Preferences to C:\cases\FS03\tout\C\Users\steven\AppData\Local\Microsoft\Edge\User Data\Default\Preferences. Error: Attempt to get an MFT record with an old reference",
        "System.IO.IOException: Attempt to get an MFT record with an old reference",
        "   at DiscUtils.Ntfs.File.Open(Int32 streamId)",
        "[2025-08-25 13:21:09.2124525 | WRN] WARNING: THERE WERE {.Count:N0} FILE COPY FAILURES! See the console log for details!!!",
        r"[2025-08-25 13:21:09.9776063 | INF] Copied 3 (Deduplicated: 1) out of 6 files in 7.7969 seconds. File copy errors: 1. See console log for details! See C:\cases\FS03\tout\2025-08-25T20_20_59_5246365_CopyLog.csv for copy details",
        "[2025-08-25 13:21:10.0012345 | INF] Total execution time: 10.4001 seconds",
    ]
    write(root, f"{run}_ConsoleLog.txt", crlf(console).encode("utf-8"))


def ws12():
    root = here / "kape-ws12"
    shutil.rmtree(root, ignore_errors=True)
    run = "2022-05-28T024344"
    tdest = r"D:\kape\tout"
    files = [(r"C:\Users\Default\NTUSER.DAT", "C/Users/Default/NTUSER.DAT", b"regf default user", "False")]
    write(root, f"{run}_CopyLog.csv", copy_log(root, tdest, files))
    console = [
        "2022-05-28 02:43:44.1234 | I | KAPE version 1.2.0.0 Author: Eric Zimmerman (kape@kroll.com)",
        "2022-05-28 02:43:44.1300 | I | KAPE directory: 'C:\\Tools\\KAPE'",
        "2022-05-28 02:43:44.1400 | I | Command line:   --tsource C: --tdest D:\\kape\\tout --target RegistryHivesUser",
        "2022-05-28 02:43:45.0000 | I | Copied 1 out of 1 files in 0.5000 seconds. See '*_CopyLog.csv' in 'D:\\kape\\tout' for copy details",
        "2022-05-28 02:43:45.1000 | F | Total execution time: 1.0000 seconds",
    ]
    write(root, f"{run}_ConsoleLog.txt", crlf(console).encode("utf-8"))


fs03()
ws12()
print("kape-fs03, kape-ws12")
