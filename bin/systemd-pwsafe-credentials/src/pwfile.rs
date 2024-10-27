use std::{io::Cursor, path::PathBuf, sync::Arc};

use pwsafer::{PwsafeKey, PwsafeReader, ReadError};
use tokio::sync::{watch, Notify};

#[derive(Clone)]
pub struct Passwords {
    inner: Arc<watch::Sender<Inner>>,
    notify: Arc<Notify>,
}

#[derive(Clone)]
pub struct PasswordReader {
    inner: watch::Receiver<Inner>,
    notify: Arc<Notify>,
}

pub struct LockRequest<'pw> {
    inner: &'pw Passwords,
}

pub struct Unlocked<'pw> {
    inner: watch::Ref<'pw, Inner>,
}

struct Inner {
    reader: PwsafeReader<Cursor<Vec<u8>>>,
    unlocked: bool,
}

impl Passwords {
    pub async fn new(from: PathBuf) -> std::io::Result<Self> {
        let raw = tokio::fs::read(from).await?;
        let reader = PwsafeReader::from_locked(Cursor::new(raw));

        let inner = Inner {
            reader,
            unlocked: false,
        };

        let notify = Arc::default();

        let (sender, _) = watch::channel(inner);
        let inner = Arc::new(sender);
        Ok(Passwords { inner, notify })
    }

    pub fn reader(&self) -> PasswordReader {
        PasswordReader {
            inner: self.inner.subscribe(),
            notify: self.notify.clone(),
        }
    }

    pub async fn as_lock_request(&self) -> Option<LockRequest<'_>> {
        self.notify.notified().await;

        // Stray request.
        if self.inner.borrow().unlocked {
            return None;
        }

        Some(LockRequest { inner: self })
    }

    /// Unconditionally unlock by a key.
    pub fn unlock(&self, key: &PwsafeKey) -> Result<(), ReadError> {
        let mut err: Result<(), ReadError> = Ok(());

        self.inner.send_if_modified(|inner| {
            if inner.unlocked {
                return false;
            }

            err = inner.reader.reread(key);
            inner.unlocked |= err.is_ok();
            err.is_ok()
        });

        err
    }
}

impl LockRequest<'_> {
    pub fn unlock(self, key: &PwsafeKey) -> Result<(), ReadError> {
        self.inner.unlock(key)
    }
}

impl PasswordReader {
    pub async fn as_unlocked(&mut self) -> Result<Unlocked<'_>, watch::error::RecvError> {
        let inner = self
            .inner
            .wait_for(|pw| {
                if pw.unlocked {
                    true
                } else {
                    self.notify.notify_one();
                    false
                }
            })
            .await?;

        Ok(Unlocked { inner })
    }
}

impl Unlocked<'_> {
    pub fn search_by_uuid(&mut self, id: uuid::Uuid) -> Option<Vec<u8>> {
        let mut fork = self.inner.reader.fork();
        let mut keydata = None;
        let mut in_matching_field = false;

        while let Some((field, data)) = fork.read_field() {
            if field == 0x1 {
                in_matching_field = data == id.into_bytes();
            }

            if field == 0x6 && in_matching_field {
                keydata = Some(data);
                break;
            }
        }

        keydata
    }
}
