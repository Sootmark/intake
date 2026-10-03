//! Paths as they existed on the collected host.

use core::fmt;

/// A path on the collected host, e.g. `C:\Windows\System32\config\SYSTEM`.
///
/// Collections store files under their own layouts (`C/Windows/…` for KAPE,
/// `uploads/auto/C%3A/Windows/…` for Velociraptor). A `HostPath` is the path
/// the file had on the machine, which is what analysts reason about.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostPath {
    drive: Option<char>,
    components: Vec<String>,
    /// A Unix path (`/etc/passwd`) rather than a Windows one.
    unix: bool,
}

/// Device prefixes Windows uses for raw volume access.
const DEVICE_PREFIXES: [&str; 2] = [r"\\.\", r"\\?\"];

impl HostPath {
    /// A path on `drive` (if known) made of `components`.
    #[must_use]
    pub fn new(drive: Option<char>, components: Vec<String>) -> Self {
        Self {
            drive: drive.map(|d| d.to_ascii_uppercase()),
            components,
            unix: false,
        }
    }

    /// A Unix path made of `components` (`["etc", "passwd"]` is `/etc/passwd`).
    #[must_use]
    pub fn unix(components: Vec<String>) -> Self {
        Self {
            drive: None,
            components,
            unix: true,
        }
    }

    /// Whether this is a Unix path.
    #[must_use]
    pub const fn is_unix(&self) -> bool {
        self.unix
    }

    /// Parse a Windows path: `C:\a\b`, `C:/a/b`, `\\.\C:\a`, `\\?\C:\a` or `\a\b`.
    #[must_use]
    pub fn parse_windows(path: &str) -> Self {
        let path = DEVICE_PREFIXES
            .iter()
            .find_map(|p| path.strip_prefix(p))
            .unwrap_or(path);
        let (drive, rest) = split_drive(path);
        let components = rest
            .split(['\\', '/'])
            .filter(|c| !c.is_empty())
            .map(str::to_owned)
            .collect();
        Self::new(drive, components)
    }

    /// The drive letter, when known.
    #[must_use]
    pub const fn drive(&self) -> Option<char> {
        self.drive
    }

    /// The last component (file name).
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        self.components.last().map(String::as_str)
    }
}

/// Split `C:rest` into the drive letter and the rest.
fn split_drive(path: &str) -> (Option<char>, &str) {
    let mut chars = path.chars();
    match (chars.next(), chars.next()) {
        (Some(letter), Some(':')) if letter.is_ascii_alphabetic() => (Some(letter), &path[2..]),
        _ => (None, path),
    }
}

impl fmt::Display for HostPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.unix {
            return write!(f, "/{}", self.components.join("/"));
        }
        if let Some(drive) = self.drive {
            write!(f, "{drive}:")?;
        }
        for component in &self.components {
            write!(f, "\\{component}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_windows_forms() {
        for raw in [
            r"C:\Windows\System32",
            "c:/Windows/System32",
            r"\\.\C:\Windows\System32",
            r"\\?\C:\Windows\System32",
        ] {
            assert_eq!(
                HostPath::parse_windows(raw).to_string(),
                r"C:\Windows\System32",
                "{raw}"
            );
        }
    }

    #[test]
    fn paths_without_a_drive_stay_rooted() {
        let path = HostPath::parse_windows(r"\Users\alice");
        assert_eq!(path.drive(), None);
        assert_eq!(path.to_string(), r"\Users\alice");
        assert_eq!(path.file_name(), Some("alice"));
    }
}
