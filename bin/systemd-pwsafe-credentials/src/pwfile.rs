use std::{io::Cursor, path::PathBuf, sync::Arc};

use pwsafer::{PwsafeKey, PwsafeReader, ReadError};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct Passwords {
    inner: Arc<Mutex<Inner>>,
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

        let inner = Arc::new(Mutex::new(inner));
        Ok(Passwords { inner })
    }

    pub async fn unlock(&self, key: &PwsafeKey) -> Result<bool, ReadError> {
        let mut inner = self.inner.lock().await;

        if inner.unlocked {
            return Ok(false);
        }

        inner.reader.reread(key)?;
        Ok(true)
    }
}
