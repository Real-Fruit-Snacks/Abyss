//! SharedBlockDevice — wraps a BlockDevice so multiple readers can share it.

use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use crate::traits::BlockDevice;

/// Inner state shared between all sub-readers.
struct SharedInner {
    device: Box<dyn BlockDevice>,
}

/// A cloneable handle to a shared BlockDevice.
/// Each clone maintains its own virtual seek position.
pub struct SharedBlockDevice {
    inner: Arc<Mutex<SharedInner>>,
    position: u64,
    size: u64,
}

impl SharedBlockDevice {
    /// Wrap a BlockDevice for shared access.
    pub fn new(device: Box<dyn BlockDevice>) -> Self {
        let size = device.size();
        Self {
            inner: Arc::new(Mutex::new(SharedInner { device })),
            position: 0,
            size,
        }
    }

    /// Create a new independent reader at position 0.
    pub fn clone_reader(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            position: 0,
            size: self.size,
        }
    }

    /// Total media size.
    pub fn size(&self) -> u64 {
        self.size
    }
}

impl Read for SharedBlockDevice {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut inner = self.inner.lock().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "lock poisoned")
        })?;
        inner.device.seek(SeekFrom::Start(self.position))?;
        let n = inner.device.read(buf)?;
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for SharedBlockDevice {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => (self.size as i64 + offset).max(0) as u64,
            SeekFrom::Current(offset) => (self.position as i64 + offset).max(0) as u64,
        };
        self.position = new_pos.min(self.size);
        Ok(self.position)
    }
}

// Static assertion: SharedBlockDevice is Send via Arc<Mutex<BlockDevice: Send>>.
#[allow(dead_code)]
const _: () = {
    fn assert_send<T: Send>() {}
    fn check() { assert_send::<SharedBlockDevice>(); }
};
