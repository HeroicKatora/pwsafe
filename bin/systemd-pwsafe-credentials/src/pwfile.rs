use std::{io::Cursor, path::PathBuf, sync::Arc};

use pwsafer::{PwsafeKey, PwsafeReader, ReadError};
use tokio::sync::watch;

#[derive(Clone)]
pub struct Passwords {
    inner: Arc<watch::Sender<Inner>>,
}

#[derive(Clone)]
pub struct PasswordReader {
    inner: watch::Receiver<Inner>,
}

pub struct Locked<'pw> {
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

        let (sender, _) = watch::channel(inner);
        let inner = Arc::new(sender);
        Ok(Passwords { inner })
    }

    pub fn reader(&self) -> PasswordReader {
        PasswordReader {
            inner: self.inner.subscribe(),
        }
    }

    pub async fn unlock(&self, key: &PwsafeKey) -> Result<(), ReadError> {
        let mut err: Result<(), ReadError> = Ok(());

        self.inner.send_if_modified(|inner| {
            if inner.unlocked {
                return false;
            }

            err = inner.reader.reread(key);
            err.is_ok()
        });

        err
    }
}

impl PasswordReader {
    pub async fn unlocked(&mut self) -> Result<Locked<'_>, watch::error::RecvError> {
        let inner = self.inner.wait_for(|pw| pw.unlocked).await?;
        Ok(Locked { inner })
    }
}
