#!/usr/bin/env python3
"""Build Collection-FS02.zip: a Velociraptor offline collection whose own
records show problems, for the collection-log tests.

Field names, JSONL layout and codes follow Velociraptor's source: the
collector test fixture vql/tools/collector/fixtures/TestCollectionWithUpload.golden,
ArtifactCollectorContext (state 2 = FINISHED) and VeloStatus (status
10 = GENERIC_ERROR). Contents are synthetic; the messages are illustrative.

    python3 make-velociraptor-fs02.py   (writes Collection-FS02.zip here)
"""

import json
import pathlib
import zipfile

T0 = 1790594700  # 2026-09-28T11:25:00Z
here = pathlib.Path(__file__).parent


def jsonl(rows):
    return "".join(json.dumps(row) + "\n" for row in rows)


context = {
    "session_id": "F.CRS2A7T0G1",
    "request": {
        "artifacts": [
            "Windows.KapeFiles.Targets",
            "Windows.EventLogs.Evtx",
            "Windows.Forensics.SRUM",
            "Windows.Registry.RDP",
        ],
        "max_upload_bytes": 1073741824,
    },
    "create_time": T0 * 1_000_000_000,
    "total_uploaded_files": 4,
    "state": 2,
    "artifacts_with_results": [
        "Windows.KapeFiles.Targets/All File Metadata",
        "Windows.KapeFiles.Targets/Uploads",
        "Windows.EventLogs.Evtx",
    ],
    "query_stats": [
        {"Artifact": "Windows.KapeFiles.Targets", "names_with_response": ["Windows.KapeFiles.Targets/Uploads"], "log_rows": 6, "result_rows": 4},
        {"Artifact": "Windows.EventLogs.Evtx", "names_with_response": ["Windows.EventLogs.Evtx"], "log_rows": 2, "result_rows": 3},
        {"Artifact": "Windows.Forensics.SRUM", "status": 10, "error_message": "srum: open C:\\Windows\\System32\\sru\\SRUDB.dat: The process cannot access the file because it is being used by another process.", "log_rows": 1},
        {"Artifact": "Windows.Registry.RDP", "log_rows": 1, "result_rows": 0},
    ],
}
client_info = {"Hostname": "FS02", "Fqdn": "FS02.corp.example", "Name": "velociraptor", "Version": "0.7.1", "BuildTime": "2026-01-10T00:00:00Z"}
log = [
    {"_ts": T0, "client_time": T0, "level": "DEFAULT", "message": "Starting collection of Windows.KapeFiles.Targets\n"},
    {"_ts": T0 + 2, "client_time": T0 + 2, "level": "WARN", "message": "glob: C:\\$Extend\\$UsnJrnl:$J is sparse: collecting ranges only\n"},
    {"_ts": T0 + 3, "client_time": T0 + 3, "level": "ERROR", "message": "upload: C:\\Windows\\System32\\config\\SAM: Access is denied.\n"},
    {"_ts": T0 + 9, "client_time": T0 + 9, "level": "ERROR", "message": "srum: open C:\\Windows\\System32\\sru\\SRUDB.dat: The process cannot access the file because it is being used by another process.\n"},
    {"_ts": T0 + 12, "client_time": T0 + 12, "level": "DEBUG", "message": "Query Stats: {\"RowsScanned\":7}\n"},
    {"_ts": T0 + 12, "client_time": T0 + 12, "level": "DEFAULT", "message": "Collected 7 rows for Windows.KapeFiles.Targets\n"},
]
evtx = b"ElfFile\0 rest of the header"
uploads = [
    ("uploads/auto/C%3A/Windows/System32/winevt/Logs/Security.evtx", ["uploads", "auto", "C:", "Windows", "System32", "winevt", "Logs", "Security.evtx"], evtx, len(evtx), ""),
    ("uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl%3A$J", ["uploads", "ntfs", "\\\\.\\C:", "$Extend", "$UsnJrnl:$J"], b"USN ranges", 4096, ""),
    ("uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl%3A$J.idx", ["uploads", "ntfs", "\\\\.\\C:", "$Extend", "$UsnJrnl:$J"], b"[]", 2, "idx"),
    # Stored short of its size: e.g. the upload limit was reached.
    ("uploads/auto/C%3A/pagefile.sys", ["uploads", "auto", "C:", "pagefile.sys"], b"partial", 8589934592, ""),
]
uploads_json = [
    {"Timestamp": "2026-09-28T09:25:05Z", "started": "2026-09-28 09:25:05 +0000 UTC", "vfs_path": "/".join(c), "_Components": c, "file_size": size, "uploaded_size": len(data) if kind != "idx" else size, "Type": kind}
    for (_, c, data, size, kind) in uploads
]

out = here / "Collection-FS02.zip"
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    fixed = (2026, 9, 28, 9, 25, 0)
    def add(name, data):
        info = zipfile.ZipInfo(name, fixed)
        info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, data)
    add("client_info.json", json.dumps(client_info, indent=1))
    add("collection_context.json", json.dumps(context, indent=1))
    add("log.json", jsonl(log))
    add("uploads.json", jsonl(uploads_json))
    for (name, _, data, _, _) in uploads:
        add(name, data)
print(out)
