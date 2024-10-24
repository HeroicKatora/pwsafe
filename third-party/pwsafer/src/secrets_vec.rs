//! An appendable version of `secrets::SecretVec`.
use secrets::SecretVec;

pub struct SecretBuffer {
    /// The inner buffer.
    inner: SecretVec<u8>,
    /// The overlay length.
    len: usize,
}

pub struct SecretCursor {
    buffer: SecretVec<u8>,
    pos: usize,
}

impl SecretBuffer {
    pub fn new() -> Self {
        SecretBuffer {
            inner: SecretVec::zero(0),
            len: 0,
        }
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        if let Some(newlen) = self.needs_grow(data) {
            self.relocate(newlen);
        }

        let mut inner = self.inner.borrow_mut();
        let len = data.len();

        inner[self.len..][..len].copy_from_slice(data);
        self.len += len;
    }

    pub fn to_owned(&self) -> SecretVec<u8> {
        let inner = self.inner.borrow();
        let mut out: SecretVec<u8> = SecretVec::zero(self.len);

        {
            let mut into = out.borrow_mut();
            into.copy_from_slice(&inner[..self.len]);
        }

        out
    }

    fn relocate(&mut self, newlen: usize) {
        let copy = self.inner.len().min(newlen);
        let mut new: SecretVec<u8> = SecretVec::zero(newlen);

        {
            let mut into = new.borrow_mut();
            let from = self.inner.borrow();
            into[..copy].copy_from_slice(&from[..copy]);
        }

        self.inner = new;
    }

    fn needs_grow(&self, data: &[u8]) -> Option<usize> {
        Self::needs_grow_to(self.inner.len(), self.len, data.len())
    }

    fn needs_grow_to(capacity: usize, len: usize, extra: usize) -> Option<usize> {
        let new_len = len.checked_add(extra).expect("capacity overflow");
        const GROWTH_FACTOR: usize = 2;

        if capacity >= new_len {
            return None;
        }

        let new_cap = capacity
            .checked_mul(GROWTH_FACTOR)
            .expect("capacity overflow");

        // Grow, at least to 32 if necessary.
        Some(new_cap.max(32))
    }
}

impl SecretCursor {
    pub fn new(buffer: SecretVec<u8>) -> Self {
        SecretCursor { buffer, pos: 0 }
    }

    pub fn with_buf<T>(&mut self, cb: impl FnOnce(&[u8], &mut usize) -> T) -> T {
        let tail = self.buffer.borrow();
        let tail = &tail[self.pos..];
        let mut consume = 0;

        let result = cb(tail, &mut consume);

        self.pos += consume;
        result
    }

    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }
}

impl From<SecretVec<u8>> for SecretCursor {
    fn from(vec: SecretVec<u8>) -> Self {
        SecretCursor::new(vec)
    }
}

impl Default for SecretCursor {
    fn default() -> Self {
        SecretCursor {
            buffer: SecretVec::zero(0),
            pos: 0,
        }
    }
}
