use crate::ArgsPwsafe;
use crate::diff::{Diff, DiffableBase, RecordDescriptor};
use crate::lockfile::{LockFile, UserInfo};

use std::{io, fs};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use eyre::Report;

use matrix_sdk::matrix_auth::MatrixSession;
use matrix_sdk::ruma::OwnedRoomId;
use pwsafer::{PwsafeKey, PwsafeReader, PwsafeWriter, PwsafeRecordField};
use serde::{Serialize, Deserialize};
use tempfile::NamedTempFile;

pub struct PwsafeDb {
    /// Cached version of the state as encoded, might be defaulted.
    state: State,
    remote: PwsafeReader<io::Cursor<Vec<u8>>>,
    /// The local edits between the synchronized shared state received from the room.
    local_diff: VecDeque<Diff>,
    /// The key, derived from the password and not yet salted & iterated.
    ///
    /// Used for reading and writing but does not contain the secret phrase itself.
    key: PwsafeKey,
    /// Runtime representation of the differential engine representing the state of the password
    /// file.
    local_diff_base: DiffableBase,
    reader_working_copy: PwsafeReader<io::Cursor<Vec<u8>>>,
    path: PathBuf,
    lock: PathBuf,
    userinfo: UserInfo,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
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

        let (state, local_diff_base, local_diff) = Self::read_state(&mut reader)?;
        let userinfo = UserInfo::new()?;

        let remote = {
            let mut write_data = io::Cursor::new(vec![]);
            let mut writer = PwsafeWriter::new(&mut write_data, reader.get_iter(), &key)?;
            writer.finish()?;

            write_data.set_position(0);
            PwsafeReader::new(write_data, &key).unwrap()
        };

        let reader_working_copy = {
            let mut write_data = io::Cursor::new(vec![]);
            let mut writer = PwsafeWriter::new(&mut write_data, reader.get_iter(), &key)?;

            let diff = Diff::empty(&local_diff_base);
            diff.apply(&mut reader, &mut writer)?;
            writer.finish()?;

            write_data.set_position(0);
            PwsafeReader::new(write_data, &key).unwrap()
        };

        let path = Path::new(&args.pwsafe).to_path_buf();
        let lock = Self::lock_file_name(&path);

        Ok(PwsafeDb {
            state,
            remote,
            local_diff: [local_diff].into_iter().collect(),
            key,
            local_diff_base,
            reader_working_copy,
            path,
            lock,
            userinfo,
        })
    }

    pub fn diff(&self, value: serde_json::Value) -> Result<Diff, Report> {
        self.local_diff_base.deserialize(value)
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

    pub fn session(&self) -> Option<&MatrixSession> {
        self.state.session.as_ref()
    }

    pub fn set_session(&mut self, session: MatrixSession) {
        self.state.session = Some(session);
    }

    pub fn room(&self) -> Option<&OwnedRoomId> {
        self.state.room.as_ref()
    }

    pub fn set_room(&mut self, room: OwnedRoomId) {
        self.state.room = Some(room);
    }

    pub fn remote_until(&self) -> Option<&Timestamp> {
        self.state.remote_until.as_ref()
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

    /// Create a new diff, by comparing the state of applying all updates with the state read from
    /// disk.
    pub fn push_diff_from_remote(&mut self)
        -> Result<Option<usize>, Report>
    {
        let mut write_data = io::Cursor::new(vec![]);
        let iter = self.reader_working_copy.get_iter();
        let mut writer = PwsafeWriter::new(&mut write_data, iter, &self.key)?;

        let local_base = self.render_diff_into(&mut writer)?;
        let local_diff = local_base.visit(&mut self.reader_working_copy)?;

        if local_diff.diff.is_empty() {
            return Ok(None);
        }

        self.local_diff.push_back(local_diff.diff);
        Ok(Some(self.local_diff.len()))
    }

    fn pop_diff(&mut self) {
        self.local_diff.pop_front();
    }

    fn render_diff_into(&mut self, finally: &mut PwsafeWriter<impl std::io::Write>)
        -> Result<DiffableBase, Report>
    {
        let state = serde_json::to_string(&self.state)?;
        let mut diffs = self.local_diff.iter();
        let mut last_diff_modified_with_state = diffs
            .next_back()
            .cloned()
            .unwrap_or_else(|| Diff::empty(&self.local_diff_base));

        let mut post_diff: PwsafeReader<_>;
        let mut pre_diff: &mut PwsafeReader<_> = &mut self.remote;

        for diff in diffs {
            let mut write_data = io::Cursor::new(vec![]);
            let mut writer = PwsafeWriter::new(&mut write_data, pre_diff.get_iter(), &self.key)?;

            diff.apply(pre_diff, &mut writer)?;
            writer.finish()?;

            write_data.set_position(0);
            post_diff = PwsafeReader::new(write_data, &self.key).unwrap();
            pre_diff = &mut post_diff;
        }

        last_diff_modified_with_state.add_state(state);
        last_diff_modified_with_state.apply(pre_diff, finally)?;

        let update = self.local_diff_base.visit(pre_diff)?;
        Ok(update.new_base)
    }
}

impl PwsafeLock<'_> {
    /// Re-Read the file, report if there was any change.
    pub fn refresh(&mut self) -> Result<(), Report> {
        let file = fs::File::open(&self.path)?;
        let mut reader = PwsafeReader::new(file, &self.key)?;

        let reader_working_copy = {
            let mut write_data = io::Cursor::new(vec![]);
            let mut writer = PwsafeWriter::new(&mut write_data, reader.get_iter(), &self.key)?;

            let diff = Diff::empty(&self.local_diff_base);
            diff.apply(&mut reader, &mut writer)?;
            writer.finish()?;

            write_data.set_position(0);
            PwsafeReader::new(write_data, &self.key).unwrap()
        };

        self.reader_working_copy = reader_working_copy;
        Ok(())
    }

    /// Modify the local file with some diff.
    pub fn apply(&mut self, diff: &Diff) -> Result<(), Report> {
        self.inner.local_diff.push_back(diff.clone());
        Ok(())
    }

    /// Rewrite the pwsafe file with the in-memory state.
    ///
    /// This restarts the inner reader.
    pub fn rewrite(&mut self) -> Result<(), Report> {
        // Implicitly checked for parent when creating lockfile path..
        let parent = self.inner.path.parent().unwrap();
        let mut tempfile = NamedTempFile::new_in(parent)?;

        {
            let iter = self.inner.reader_working_copy.get_iter();
            let mut writer = PwsafeWriter::new(&mut tempfile, iter, &self.key)?;
            self.inner.render_diff_into(&mut writer)?;
            writer.finish()?;
        }

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
    session: Option<MatrixSession>,
    #[serde(default)]
    room: Option<OwnedRoomId>,
    /// The timestamp of the last remote change which should be regarded as considered.
    #[serde(default)]
    remote_until: Option<Timestamp>,
}
