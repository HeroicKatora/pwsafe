use crate::ArgsPwsafe;
use crate::diff::{Diff, DiffableBase, RecordDescriptor};
use crate::lockfile::{LockFile, UserInfo};

use std::{io, fs};
use std::path::{Path, PathBuf};

use eyre::Report;

use matrix_sdk::Session;
use matrix_sdk::ruma::OwnedRoomId;
use pwsafer::{PwsafeKey, PwsafeReader, PwsafeWriter, PwsafeRecordField};
use serde::{Serialize, Deserialize};
use tempfile::NamedTempFile;

pub struct PwsafeDb {
    /// Cached version of the state as encoded, might be defaulted.
    state: State,
    remote: PwsafeReader<io::Cursor<Vec<u8>>>,
    /// Runtime representation of the differential engine representing the state of the password
    /// file.
    diff_base: DiffableBase,
    /// The local edits between the synchronized shared state received from the room.
    local_diff: Diff,
    /// The key, derived from the password and not yet salted & iterated.
    ///
    /// Used for reading and writing but does not contain the secret phrase itself.
    key: PwsafeKey,
    reader: PwsafeReader<fs::File>,
    path: PathBuf,
    lock: PathBuf,
    userinfo: UserInfo,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Timestamp {
    /// The relative timestamp order of the event.
    pub ts_ms: u64,
    /// A unique identifier for that event.
    pub unique: String,
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

        let (state, diff_base, local_diff) = Self::read_state(&mut reader)?;
        let userinfo = UserInfo::new()?;

        let remote = {
            let mut write_data = io::Cursor::new(vec![]);
            let mut writer = PwsafeWriter::new(&mut write_data, reader.get_iter(), &key)?;
            writer.finish()?;

            write_data.set_position(0);
            PwsafeReader::new(write_data, &key).unwrap()
        };

        let path = Path::new(&args.pwsafe).to_path_buf();
        let lock = Self::lock_file_name(&path);

        Ok(PwsafeDb {
            state,
            remote,
            diff_base,
            local_diff,
            reader,
            key,
            path,
            lock,
            userinfo,
        })
    }

    pub fn diff(&self, value: serde_json::Value) -> Result<Diff, Report> {
        self.diff_base.deserialize(value)
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

    pub fn room(&self) -> Option<&OwnedRoomId> {
        self.state.room.as_ref()
    }

    pub fn set_room(&mut self, room: OwnedRoomId) {
        self.state.room = Some(room);
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
        -> Result<(State, DiffableBase, Diff), Report>
    {
        let diff_base = DiffableBase::default();
        let initial = diff_base.visit(reader)?;
        let state = Self::state_from_record(&initial.state_record)?;
        Ok((state, initial.new_base, initial.diff))
    }

    fn state_from_record(record: &RecordDescriptor) -> Result<State, Report> {
        if record.fields.is_empty() {
            return Ok(State::default());
        }

        let serialized = record.fields
            .iter()
            .find_map(|field| {
                if let PwsafeRecordField::Notes(note) = &field.pwsafe {
                    Some(note)
                } else {
                    None
                }
            });

        let Some(serialized) = serialized else {
            return Ok(State::default());
        };

        let state: State = serde_json::from_str(serialized)?;
        Ok(state)
    }
}

impl PwsafeLock<'_> {
    /// Rewrite the pwsafe file with the in-memory state.
    ///
    /// This restarts the inner reader.
    pub fn rewrite(&mut self) -> Result<(), Report> {
        let mut diff = self.local_diff.clone();
        let state = serde_json::to_string(&self.state)?;

        // Implicitly checked for parent when creating lockfile path..
        let parent = self.inner.path.parent().unwrap();
        let mut tempfile = NamedTempFile::new_in(parent)?;
        let mut writer = PwsafeWriter::new(&mut tempfile, self.reader.get_iter(), &self.key)?;

        diff.add_state(state);
        diff.apply(&mut self.reader, &mut writer)?;
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

    /// Update the database with remote events.
    pub fn rebase(
        &mut self,
        diffs: &[Diff],
        time: &[Timestamp],
    ) -> Result<(), Report> {
        assert_eq!(diffs.len(), time.len());

        for (diff, ts) in diffs.iter().zip(time) {
            let mut write_data = io::Cursor::new(vec![]);
            let mut writer = PwsafeWriter::new(&mut write_data, self.remote.get_iter(), &self.key)?;

            diff.apply(&mut self.remote, &mut writer)?;
            writer.finish()?;

            write_data.set_position(0);
            self.remote = PwsafeReader::new(write_data, &self.key)?;
            self.state.remote_until = Some(ts.clone());
        }

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

#[derive(Deserialize, Serialize, Default)]
struct State {
    /// An existing matrix session related to this pwsafe-matrix database.
    #[serde(default)]
    session: Option<Session>,
    #[serde(default)]
    room: Option<OwnedRoomId>,
    /// The timestamp of the last remote change which should be regarded as considered.
    #[serde(default)]
    remote_until: Option<Timestamp>,
}
