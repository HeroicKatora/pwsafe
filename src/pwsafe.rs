use crate::ArgsPwsafe;
use crate::diff::{DiffableBase, RecordDescriptor};
use crate::lockfile::{LockFile, UserInfo};

use std::fs;
use std::path::{Path, PathBuf};

use eyre::Report;

use matrix_sdk::Session;
use matrix_sdk::ruma::OwnedRoomId;
use pwsafer::{PwsafeKey, PwsafeReader, PwsafeWriter};
use serde::{Serialize, Deserialize};
use tempfile::NamedTempFile;

pub struct PwsafeDb {
    /// Cached version of the state as encoded, might be defaulted.
    state: State,
    /// Runtime representation of the differential engine representing the state of the password
    /// file.
    diff: DiffableBase,
    /// The key, derived from the password and not yet salted & iterated.
    ///
    /// Used for reading and writing but does not contain the secret phrase itself.
    key: PwsafeKey,
    reader: PwsafeReader<fs::File>,
    path: PathBuf,
    lock: PathBuf,
    userinfo: UserInfo,
}

/// A pwsafe db file, holding a lock.
///
/// Allows running operations that would otherwise race, such as modifying the underlying file.
pub struct PwsafeLock<'lt> {
    inner: &'lt mut PwsafeDb,
    /// Held for RAII purposes, protects our lock state.
    ///
    /// Contains a handle to the lockfile path, which we might be interested in? I don't know.
    #[allow(dead_code)]
    lockfile: LockFile,
}

impl PwsafeDb {
    pub fn open(args: &ArgsPwsafe) -> Result<Self, Report> {
        let newly_read_passwd;
        let passwd = if let Some(path) = &args.passwd_file {
            newly_read_passwd = fs::read(path)?;
            newly_read_passwd.as_slice()
        } else {
            args.passwd.as_bytes()
        };

        let file = fs::File::open(&args.pwsafe)?;
        let key = PwsafeKey::new(passwd);
        let mut reader = PwsafeReader::new(file, &key)?;

        let (state, diff) = Self::read_state(&mut reader)?;
        let userinfo = UserInfo::new()?;

        let path = Path::new(&args.pwsafe).to_path_buf();
        let lock = Self::lock_file_name(&path);

        Ok(PwsafeDb {
            state,
            diff,
            reader,
            key,
            path,
            lock,
            userinfo,
        })
    }

    pub fn with_lock<V>(&mut self, f: impl FnOnce(PwsafeLock) -> Result<V, Report>)
        -> Result<V, Report>
    {
        let lockfile = LockFile::create(self.lock.clone(), &self.userinfo)?;

        f(PwsafeLock {
            inner: self,
            lockfile,
        })
    }

    pub fn session(&self) -> Option<&Session> {
        self.state.session.as_ref()
    }

    pub fn set_session(&mut self, session: Session) {
        self.state.session = Some(session);
    }

    /// Get the lock file, also used by pwsafe itself.
    ///
    /// Should only be called after having opened the file, it asserts that the file name is
    /// plausible.
    ///
    /// See: <https://github.com/pwsafe/pwsafe/blob/717c019b93c664876890a41a8f28d5c3eae95ef0/src/os/mac/file.cpp#L235C1-L252>
    fn lock_file_name(path: &Path) -> PathBuf {
        let extension = if path.extension().and_then(|x| x.to_str()) == Some(".cfg") {
            "cfg.plk"
        } else {
            ".plk"
        };

        let mut copy = path.to_path_buf();
        copy.set_extension(extension);
        copy
    }

    fn read_state(reader: &mut PwsafeReader<fs::File>)
        -> Result<(State, DiffableBase), Report>
    {
        let diff = DiffableBase::default();
        let initial = diff.visit(reader)?;
        let state = Self::state_from_record(&initial.state_record)?;
        Ok((state, initial.new_base))
    }

    fn state_from_record(_: &RecordDescriptor) -> Result<State, Report> {
        todo!()
    }
}

impl PwsafeLock<'_> {
    /// Rewrite the pwsafe file with the in-memory state.
    ///
    /// This restarts the inner reader.
    pub fn rewrite(&mut self) -> Result<(), Report> {
        // Implicitly checked for parent when creating lockfile path..
        let parent = self.inner.path.parent().unwrap();
        let mut tempfile = NamedTempFile::new_in(parent)?;

        self.reader.restart();
        let iter = self.reader.get_iter();
        let mut writer = PwsafeWriter::new(&mut tempfile, iter, &self.key)?;

        while let Some((ty, data)) = self.reader.read_field()? {
            writer.write_field(ty, &data)?;
        }

        writer.finish()?;
        drop(writer);

        // Finally, atomically move to this new path.
        let stdfile = tempfile.persist(&self.inner.path)?;
        // And ensure that data and metadata is propagated even if we afterwards release the lock
        // file, so that the new data is surely read. FIXME: this **really** should use asyncio and
        // tokio, there's no point in waiting the whole program several milliseconds here and we
        // can definitely do useful IO with the Matrix server in the meantime.
        stdfile.sync_all()?;

        Ok(())
    }
}

impl core::ops::Deref for PwsafeLock<'_> {
    type Target = PwsafeDb;
    fn deref(&self) -> &PwsafeDb {
        &*self.inner
    }
}

impl core::ops::DerefMut for PwsafeLock<'_> {
    fn deref_mut(&mut self) -> &mut PwsafeDb {
        &mut *self.inner
    }
}

#[derive(Deserialize, Serialize)]
struct State {
    /// An existing matrix session related to this pwsafe-matrix database.
    #[serde(default)]
    session: Option<Session>,
    #[serde(default)]
    room: Option<OwnedRoomId>,
}
