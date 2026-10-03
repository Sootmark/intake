//! KAPE target collections: `<run>_ConsoleLog.txt` (the only record of copy
//! failures) and `<run>_CopyLog.csv` (every file copied, with its SHA-1),
//! written next to the drive-letter folders.
//!
//! Two console formats exist: NLog up to KAPE 1.2
//! (`2022-05-28 02:43:44.1234 | I | message`) and Serilog from 1.3
//! (`[2025-08-25 13:21:00.1807432 | INF] message`). Console times are the
//! host's wall clock with no zone; the run timestamp in file names is UTC.
//! Lines not starting with a timestamp continue the previous message (stack
//! traces). See Eric Zimmerman's KapeDocs, "Log files".

use common::time::{days_from_civil, Precision, Ts};

use super::{CollectionLog, CollectorFiles, Failure, LogLine, Outcome, RecordedHash};
use crate::layout::LayoutKind;

const CONSOLE_LOG: &str = "_ConsoleLog.txt";
const COPY_LOG: &str = "_CopyLog.csv";
const COPY_FAILED: &str = "Could not copy file ";
const COPY_FAILED_REASON: &str = ". Error: ";
const VANISHED_PREFIX: &str = "File ";
const VANISHED_SUFFIX: &str = " does not exist! Skipping!";
/// Logged at error level when a compound target repeats a target: benign.
const ALREADY_PROCESSED: &str = "already processed. Skipping!";
const VERSION_PREFIX: &str = "KAPE version ";
const COMMAND_LINE: &str = "Command line:";
const FINISHED: &str = "Total execution time";
const TICKS_PER_SECOND: i64 = 10_000_000;
const TICKS_PER_DAY: i64 = 86_400 * TICKS_PER_SECOND;
const UTF8_BOM: &str = "\u{feff}";

pub(super) fn read(files: &CollectorFiles<'_>) -> CollectionLog {
    let mut log = CollectionLog::new(LayoutKind::Kape);
    let top_level = |suffix: &str| {
        let mut found: Vec<_> = files
            .entries
            .iter()
            .filter(|e| {
                let name = files.relative(&e.path);
                !name.contains('/') && name.ends_with(suffix)
            })
            .collect();
        found.sort_by(|a, b| a.path.cmp(&b.path));
        found
    };
    let consoles = top_level(CONSOLE_LOG);
    let copy_logs = top_level(COPY_LOG);
    log.started = consoles
        .iter()
        .chain(&copy_logs)
        .filter_map(|e| run_time(files.relative(&e.path)))
        .min_by_key(Ts::ticks);
    if consoles.is_empty() {
        log.gaps.push(
            "no *_ConsoleLog.txt: KAPE records copy failures only there \
             (with --zip or --vhdx it is kept next to the container)"
                .to_owned(),
        );
    }
    let mut summary = Summary::default();
    for entry in consoles {
        if let Some(text) = files.read_text(entry, &mut log) {
            read_console(&text, &mut log, &mut summary);
        }
    }
    for entry in copy_logs {
        if let Some(text) = files.read_text(entry, &mut log) {
            read_copy_log(&text, &mut log);
        }
    }
    summary.check(&log);
    log.gaps.extend(summary.gaps);
    log
}

/// The console's closing totals, to check against what was recorded.
#[derive(Default)]
struct Summary {
    /// `Copied N (Deduplicated: D) out of T files`.
    copied: Option<u64>,
    deduplicated: u64,
    total: Option<u64>,
    gaps: Vec<String>,
}

impl Summary {
    fn check(&mut self, log: &CollectionLog) {
        let (Some(copied), Some(total)) = (self.copied, self.total) else {
            return;
        };
        if log.files_recorded > 0 && log.files_recorded != copied {
            self.gaps.push(format!(
                "the CopyLog lists {} files; the console reports {copied} copied",
                log.files_recorded
            ));
        }
        // Numbers come from the evidence: never trust them not to overflow.
        let accounted = copied
            .saturating_add(self.deduplicated)
            .saturating_add(log.failed.len() as u64)
            .saturating_add(log.without_results.len() as u64);
        if accounted < total {
            self.gaps.push(format!(
                "{} of {total} files found are neither copied, deduplicated, failed nor reported missing",
                total - accounted
            ));
        }
    }
}

fn read_console(text: &str, log: &mut CollectionLog, summary: &mut Summary) {
    for line in text.lines().map(|l| l.trim_start_matches(UTF8_BOM)) {
        // Lines without a timestamp continue the previous message.
        let Some((time, level, message)) = console_line(line) else {
            continue;
        };
        let message = message.trim();
        if let Some(version) = message.strip_prefix(VERSION_PREFIX) {
            log.version = version.split_whitespace().next().map(str::to_owned);
        } else if let Some(arguments) = message.strip_prefix(COMMAND_LINE) {
            log.requested = targets(arguments);
        } else if message.starts_with(FINISHED) {
            log.outcome = Outcome::Completed;
        } else if let Some(failure) = copy_failure(message) {
            log.failed.push(failure);
        } else if let Some(path) = message
            .strip_prefix(VANISHED_PREFIX)
            .and_then(|m| m.strip_suffix(VANISHED_SUFFIX))
        {
            log.without_results.push(path.to_owned());
        } else if let Some(totals) = message.strip_prefix("Copied ") {
            read_totals(totals, summary);
        }
        let is_error = match level {
            Level::Error => !message.ends_with(ALREADY_PROCESSED),
            // NLog logged the final timing line as fatal.
            Level::Fatal => !message.starts_with(FINISHED),
            Level::Warning | Level::Other => message.starts_with(COPY_FAILED),
        };
        if !is_error {
            if level == Level::Warning {
                log.warning_count += 1;
            }
            continue;
        }
        log.log_error(LogLine {
            time,
            message: message.to_owned(),
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Error,
    Fatal,
    Warning,
    Other,
}

/// `[ts | LVL] message` (Serilog) or `ts | L | message` (NLog).
fn console_line(line: &str) -> Option<(Option<Ts>, Level, &str)> {
    let (time, level, message) = if let Some(rest) = line.strip_prefix('[') {
        let (head, message) = rest.split_once("] ")?;
        let (time, level) = head.split_once(" | ")?;
        (time, level, message)
    } else {
        let (time, rest) = line.split_once(" | ")?;
        let (level, message) = rest.split_once(" | ")?;
        (time, level, message)
    };
    let time = local_time(time.trim())?;
    let level = match level.trim() {
        "ERR" | "E" => Level::Error,
        "FTL" | "F" => Level::Fatal,
        "WRN" | "W" => Level::Warning,
        _ => Level::Other,
    };
    Some((Some(time), level, message))
}

/// `Could not copy file <source> to <destination>. Error: <reason>`.
fn copy_failure(message: &str) -> Option<Failure> {
    let rest = message.strip_prefix(COPY_FAILED)?;
    let (paths, reason) = rest.rsplit_once(COPY_FAILED_REASON)?;
    // Paths may contain " to ": split before the first absolute destination.
    let split = paths
        .match_indices(" to ")
        .map(|(at, _)| at)
        .find(|&at| is_absolute(&paths[at + 4..]))?;
    Some(Failure {
        item: paths[..split].to_owned(),
        reason: reason.trim().to_owned(),
    })
}

fn is_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with("\\\\")
        || (bytes.len() > 2 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == b":\\")
}

/// `N (Deduplicated: D) out of T files …` or `N out of T files …`.
fn read_totals(totals: &str, summary: &mut Summary) {
    let number = |text: &str| text.trim().replace(',', "").parse::<u64>().ok();
    let Some((head, tail)) = totals.split_once(" out of ") else {
        return;
    };
    let (copied, deduplicated) = match head.split_once(" (Deduplicated: ") {
        Some((copied, rest)) => (copied, rest.trim_end_matches(')')),
        None => (head, "0"),
    };
    summary.copied = number(copied);
    summary.deduplicated = number(deduplicated).unwrap_or(0);
    summary.total = tail.split_whitespace().next().and_then(number);
}

/// The targets named after `--target` on the logged command line.
fn targets(arguments: &str) -> Vec<String> {
    let mut words = arguments.split_whitespace();
    while let Some(word) = words.next() {
        if word.eq_ignore_ascii_case("--target") {
            return words
                .next()
                .unwrap_or_default()
                .split(',')
                .filter(|t| !t.is_empty())
                .map(str::to_owned)
                .collect();
        }
    }
    Vec::new()
}

fn read_copy_log(text: &str, log: &mut CollectionLog) {
    let mut lines = text.trim_start_matches(UTF8_BOM).lines();
    let Some(header) = lines.next().map(csv_fields) else {
        return;
    };
    let column = |name: &str| header.iter().position(|h| h == name);
    let (Some(source), Some(destination), Some(size), Some(sha1)) = (
        column("SourceFile"),
        column("DestinationFile"),
        column("FileSize"),
        column("SourceFileSha1"),
    ) else {
        log.gaps
            .push("CopyLog without the expected columns".to_owned());
        return;
    };
    let mut unmatched = 0u64;
    for fields in lines.filter(|l| !l.trim().is_empty()).map(csv_fields) {
        let field = |index: usize| fields.get(index).map_or("", String::as_str);
        log.files_recorded += 1;
        match stored_path(field(source), field(destination)) {
            Some(path) => log.hashes.push(RecordedHash {
                path,
                algorithm: "sha1",
                hex: field(sha1).to_ascii_lowercase(),
                size: field(size).parse().unwrap_or(0),
            }),
            None => unmatched += 1,
        }
    }
    if unmatched > 0 {
        log.gaps.push(format!(
            "{unmatched} CopyLog rows could not be matched to a stored file (hash not checkable)"
        ));
    }
}

/// Where KAPE stored a copied file, relative to its destination folder:
/// `<drive>/<directories of the source>/<stored name>`. The stored name can
/// differ from the source name (`$UsnJrnl:$J` is stored as `$J`), so it's
/// taken from the destination, found as the drive-letter folder at the
/// source's depth.
fn stored_path(source: &str, destination: &str) -> Option<String> {
    let source: Vec<&str> = source.split('\\').filter(|c| !c.is_empty()).collect();
    let destination: Vec<&str> = destination.split('\\').filter(|c| !c.is_empty()).collect();
    let drive = source.first()?.strip_suffix(':')?;
    let start = destination.len().checked_sub(source.len())?;
    (destination.get(start) == Some(&drive)).then(|| destination[start..].join("/"))
}

/// Fields of one CSV line; double quotes quote, `""` escapes a quote.
fn csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.trim_end_matches('\r').chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            ('"', _) => quoted = !quoted,
            (',', false) => fields.push(std::mem::take(&mut field)),
            _ => field.push(c),
        }
    }
    fields.push(field);
    fields
}

/// `2025-08-25 13:21:00.1807432` as a wall-clock time (zone unknown).
fn local_time(text: &str) -> Option<Ts> {
    let (date, time) = text.split_once(' ')?;
    let ticks = civil_ticks(date, time)?;
    Some(Ts::from_local_ticks(ticks, Precision::Tick))
}

/// The UTC run time from a log name: `2025-08-25T20_20_59_5246365_…` (1.3+)
/// or `2022-05-28T024344_…` (earlier).
fn run_time(name: &str) -> Option<Ts> {
    let (date, rest) = name.split_once('T')?;
    let time: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '_')
        .collect();
    let time = time.trim_end_matches('_');
    let digits: Vec<&str> = time.split('_').collect();
    let clock = match digits.as_slice() {
        [h, m, s, fraction] => format!("{h}:{m}:{s}.{fraction}"),
        [compact] if compact.len() == 6 => {
            format!("{}:{}:{}", &compact[..2], &compact[2..4], &compact[4..])
        }
        _ => return None,
    };
    let ticks = civil_ticks(date, &clock)?;
    Some(Ts::from_ticks(ticks, Precision::Tick))
}

/// Ticks since 1970 for `yyyy-MM-dd` and `HH:mm:ss[.fraction]`, counting
/// the wall clock as UTC.
fn civil_ticks(date: &str, time: &str) -> Option<i64> {
    let mut date_parts = date.split('-').map(str::parse::<i64>);
    let (year, month, day) = (
        date_parts.next()?.ok()?,
        date_parts.next()?.ok()?,
        date_parts.next()?.ok()?,
    );
    let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
    let mut clock_parts = clock.split(':').map(str::parse::<i64>);
    let (hour, minute, second) = (
        clock_parts.next()?.ok()?,
        clock_parts.next()?.ok()?,
        clock_parts.next()?.ok()?,
    );
    let valid = (1..=9999).contains(&year)
        && (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour < 24
        && minute < 60
        && second < 61;
    if !valid || fraction.len() > 7 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let fraction_ticks = format!("{fraction:0<7}").parse::<i64>().ok()?;
    let days = days_from_civil(year, u32::try_from(month).ok()?, u32::try_from(day).ok()?);
    days.checked_mul(TICKS_PER_DAY)?
        .checked_add((hour * 3600 + minute * 60 + second) * TICKS_PER_SECOND + fraction_ticks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_both_console_formats() {
        let (time, level, message) = console_line(
            "[2025-06-12 04:39:06.2124525 | FTL] Could not copy file C:\\a to D:\\b. Error: x",
        )
        .unwrap();
        assert_eq!(level, Level::Fatal);
        assert_eq!(
            time.unwrap().to_iso8601().as_deref(),
            Some("2025-06-12T04:39:06.2124525")
        );
        assert!(message.starts_with(COPY_FAILED));
        let (time, level, _) = console_line("2022-05-28 02:43:44.1234 | W | Flushing...").unwrap();
        assert_eq!(level, Level::Warning);
        assert_eq!(
            time.unwrap().to_iso8601().as_deref(),
            Some("2022-05-28T02:43:44.1234000")
        );
        assert!(console_line("   at DiscUtils.Ntfs.File.Open()").is_none());
        assert!(console_line("System.IO.IOException: bad | thing | here").is_none());
    }

    #[test]
    fn copy_failures_keep_paths_with_to_in_them() {
        let failure = copy_failure(
            "Could not copy file C:\\Users\\a\\How to\\Preferences to D:\\out\\C\\Users\\a\\How to\\Preferences. \
             Error: Attempt to get an MFT record with an old reference",
        )
        .unwrap();
        assert_eq!(failure.item, "C:\\Users\\a\\How to\\Preferences");
        assert_eq!(
            failure.reason,
            "Attempt to get an MFT record with an old reference"
        );
    }

    #[test]
    fn run_times_from_both_name_schemes() {
        let new = run_time("2025-08-25T20_20_59_5246365_CopyLog.csv").unwrap();
        assert_eq!(
            new.to_iso8601().as_deref(),
            Some("2025-08-25T20:20:59.5246365Z")
        );
        let old = run_time("2022-05-28T024344_ConsoleLog.txt").unwrap();
        assert_eq!(
            old.to_iso8601().as_deref(),
            Some("2022-05-28T02:43:44.0000000Z")
        );
        assert!(run_time("notes.txt").is_none());
    }

    #[test]
    fn stored_paths_follow_the_destination_name() {
        assert_eq!(
            stored_path(
                "C:\\Users\\Default\\NTUSER.DAT",
                "C:\\temp\\tout\\C\\Users\\Default\\NTUSER.DAT"
            )
            .as_deref(),
            Some("C/Users/Default/NTUSER.DAT")
        );
        assert_eq!(
            stored_path("G:\\$Extend\\$UsnJrnl:$J", "D:\\kape\\G\\$Extend\\$J").as_deref(),
            Some("G/$Extend/$J")
        );
        assert_eq!(stored_path("C:\\a\\b", "D:\\LongFileNames\\x"), None);
    }

    #[test]
    fn csv_quoting() {
        assert_eq!(csv_fields("a,\"b,c\",\"d\"\"e\"\r"), ["a", "b,c", "d\"e"]);
        assert_eq!(csv_fields(""), [""]);
    }

    #[test]
    fn totals_with_and_without_duplicates() {
        let mut summary = Summary::default();
        read_totals(
            "1,151 (Deduplicated: 260) out of 1,413 files in 91.3759 seconds. File copy errors: 1.",
            &mut summary,
        );
        assert_eq!(
            (summary.copied, summary.deduplicated, summary.total),
            (Some(1151), 260, Some(1413))
        );
        read_totals("2 out of 2 files in 0.5 seconds", &mut summary);
        assert_eq!(
            (summary.copied, summary.deduplicated, summary.total),
            (Some(2), 0, Some(2))
        );
    }

    #[test]
    fn targets_from_the_command_line() {
        assert_eq!(
            targets(
                "  --tsource C: --tdest C:\\out --tflush --target OpenSSHClient,!SANS_Triage --gui"
            ),
            ["OpenSSHClient", "!SANS_Triage"]
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

        #[test]
        fn hostile_logs_never_panic(text in r#"(\PC|\r|\n|\||\[|\]|,|"|:|\\){0,400}"#) {
            let mut log = CollectionLog::new(LayoutKind::Kape);
            let mut summary = Summary::default();
            read_console(&text, &mut log, &mut summary);
            read_copy_log(&text, &mut log);
            summary.check(&log);
            let _ = run_time(&text);
            let _ = local_time(&text);
            let _ = copy_failure(&text);
            let _ = stored_path(&text, &text);
        }

        #[test]
        fn huge_totals_never_panic(
            copied in proptest::prelude::any::<u64>(),
            deduplicated in proptest::prelude::any::<u64>(),
            total in proptest::prelude::any::<u64>(),
        ) {
            let line = format!(
                "[2025-01-01 00:00:00.0 | INF] Copied {copied} (Deduplicated: {deduplicated}) out of {total} files"
            );
            let mut log = CollectionLog::new(LayoutKind::Kape);
            log.files_recorded = 1;
            let mut summary = Summary::default();
            read_console(&line, &mut log, &mut summary);
            summary.check(&log);
        }

        #[test]
        fn shaped_console_lines_never_panic(
            year in "[0-9]{1,12}", rest in "[0-9 :.-]{0,30}", level in "(ERR|FTL|WRN|INF|E|F|W|I|X)",
            message in "(Could not copy file |File |Copied |Command line:)?\\PC{0,80}",
        ) {
            let line = format!("[{year}-{rest} | {level}] {message}\n{year}-{rest} | {level} | {message}");
            let mut log = CollectionLog::new(LayoutKind::Kape);
            read_console(&line, &mut log, &mut Summary::default());
        }
    }
}
