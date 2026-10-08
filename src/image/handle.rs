//! One disk, read by many volumes.

use std::cell::RefCell;
use std::io::{self, Read, Seek, SeekFrom};
use std::rc::Rc;

use super::Disk;

/// A handle on a disk shared with other handles: a window of it with a
/// position of its own, seeked to before every read. Every volume, and
/// every shadow copy's view of one, owns its reader of the one disk, so a
/// shadow copy's view is built once and kept, rather than once per file
/// read.
///
/// The disk is borrowed only for the length of one seek and read, so
/// handles never hold it while another reads.
#[derive(Clone)]
pub(super) struct DiskHandle {
    disk: Rc<RefCell<Box<dyn Disk>>>,
    start: u64,
    len: u64,
    position: u64,
}

impl DiskHandle {
    /// A handle on the whole of `disk`, `len` bytes long.
    pub(super) fn new(disk: Box<dyn Disk>, len: u64) -> Self {
        Self {
            disk: Rc::new(RefCell::new(disk)),
            start: 0,
            len,
            position: 0,
        }
    }

    /// A handle on `len` bytes of the same disk from `start` (a
    /// partition), at its start.
    pub(super) fn window(&self, start: u64, len: u64) -> Self {
        Self {
            disk: Rc::clone(&self.disk),
            start: self.start.saturating_add(start),
            len,
            position: 0,
        }
    }
}

impl Read for DiskHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.len.saturating_sub(self.position);
        let wanted = buf
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        if wanted == 0 {
            return Ok(0);
        }
        let mut disk = self.disk.borrow_mut();
        disk.seek(SeekFrom::Start(self.start + self.position))?;
        let read = disk.read(&mut buf[..wanted])?;
        self.position += read as u64;
        Ok(read)
    }
}

impl Seek for DiskHandle {
    fn seek(&mut self, target: SeekFrom) -> io::Result<u64> {
        let position = match target {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.len.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
        };
        self.position = position
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn disk() -> DiskHandle {
        DiskHandle::new(Box::new(Cursor::new((0u8..100).collect::<Vec<_>>())), 100)
    }

    #[test]
    fn handles_keep_their_own_positions() {
        let mut whole = disk();
        let mut part = whole.window(10, 5);
        let mut byte = [0; 1];
        whole.seek(SeekFrom::Start(50)).unwrap();
        part.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [10]);
        whole.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [50]);
        part.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [11]);
    }

    #[test]
    fn a_window_ends_where_its_partition_does() {
        let mut part = disk().window(10, 5);
        let mut out = Vec::new();
        part.read_to_end(&mut out).unwrap();
        assert_eq!(out, [10, 11, 12, 13, 14]);
        part.seek(SeekFrom::End(-1)).unwrap();
        assert_eq!(part.read(&mut [0; 4]).unwrap(), 1);
        assert!(part.seek(SeekFrom::Current(-10)).is_err());
    }
}
