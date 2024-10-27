//! An appendable version of `secrets::SecretVec`.
use secrets::{SecretBox, SecretVec};
use std::sync::Arc;

pub struct SecretBuffer {
    /// The inner buffer.
    inner: SecretVec<u8>,
    /// The overlay length.
    len: usize,
}

#[derive(Clone)]
pub struct SecretCursor {
    buffer: Arc<SecretBuffer>,
    pos: usize,
}

pub struct SecretArray<const N: usize> {
    inner: SecretBox<[u8; N]>,
}

// Safety: this was _forgotten_ by `secrets` (unresponsive for 3 years)
unsafe impl Send for SecretBuffer {}
unsafe impl Send for SecretCursor {}
unsafe impl<const N: usize> Send for SecretArray<N> {}

impl SecretBuffer {
    pub fn new() -> Self {
        SecretBuffer {
            inner: SecretVec::zero(0),
            len: 0,
        }
    }

    pub fn with_encrypted_data_destructive(encrypted: &mut [u8]) -> Self {
        let len = encrypted.len();

        SecretBuffer {
            inner: SecretVec::from(encrypted),
            len,
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

    pub fn with_buf_mut<T>(&mut self, cb: impl FnOnce(&mut [u8]) -> T) -> T {
        let mut head = self.inner.borrow_mut();
        let head = &mut head[..self.len];
        cb(head)
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
            .expect("capacity overflow")
            .max(new_len);

        // Grow, at least to 32 if necessary.
        Some(new_cap.max(32))
    }
}

impl<const N: usize> SecretArray<N> {
    pub fn zero() -> Self {
        SecretArray {
            inner: SecretBox::zero(),
        }
    }

    pub fn with_buf<T>(&self, cb: impl FnOnce(&[u8; N]) -> T) -> T {
        let head = self.inner.borrow();
        cb(&*head)
    }

    pub fn with_buf_mut<T>(&mut self, cb: impl FnOnce(&mut [u8; N]) -> T) -> T {
        let mut head = self.inner.borrow_mut();
        cb(&mut *head)
    }
}

impl Clone for SecretBuffer {
    fn clone(&self) -> SecretBuffer {
        let mut out = SecretBuffer {
            inner: SecretVec::zero(self.inner.len()),
            len: 0,
        };

        out.clone_from(self);
        out
    }

    fn clone_from(&mut self, from: &SecretBuffer) {
        debug_assert!(from.len <= from.inner.len());

        if let Some(new_cap) = Self::needs_grow_to(self.inner.len(), 0, from.len) {
            self.relocate(new_cap);
        }

        self.len = from.len;
        debug_assert!(self.len <= self.inner.len());

        {
            let mut into = self.inner.borrow_mut();
            let from = from.inner.borrow();

            into[..self.len].copy_from_slice(&from[..self.len]);
        }
    }
}

impl SecretCursor {
    pub fn with_buf<T>(&mut self, cb: impl FnOnce(&[u8], &mut usize) -> T) -> T {
        let tail = self.buffer.inner.borrow();
        let tail = &tail[self.pos..self.buffer.len];
        let mut consume = 0;

        let result = cb(tail, &mut consume);

        self.pos += consume;
        result
    }

    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }
}

impl Default for SecretBuffer {
    fn default() -> Self {
        SecretBuffer::new()
    }
}

impl From<SecretBuffer> for SecretCursor {
    fn from(buffer: SecretBuffer) -> Self {
        SecretCursor {
            buffer: Arc::new(buffer),
            pos: 0,
        }
    }
}

impl Default for SecretCursor {
    fn default() -> Self {
        Self::from(SecretBuffer::default())
    }
}
