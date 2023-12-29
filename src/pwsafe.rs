use crate::ArgsPwsafe;
use crate::diff::{DiffableBase, RecordDescriptor};
use crate::lockfile::{LockFile, UserInfo};

use std::fs;
use std::path::{Path, PathBuf};

use eyre::Report;

use matrix_sdk::Session;
use matrix_sdk::ruma::OwnedRoomId;
use pwsafer::PwsafeReader;

use serde::{Serialize, Deserialize};

pub struct PwsafeDb {
    /// Cached version of the state as encoded, might be defaulted.
    state: State,
    /// Runtime representation of the differential engine representing the state of the password
    /// file.
    diff: DiffableBase,
    reader: PwsafeReader<fs::File>,
    path: PathBuf,
    lock: PathBuf,
    userinfo: UserInfo,
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
        let mut reader = PwsafeReader::new(file, passwd)?;

        let (state, diff) = Self::read_state(&mut reader)?;
        let userinfo = UserInfo::new()?;

        let path = Path::new(&args.pwsafe).to_path_buf();
        let lock = Self::lock_file_name(&path);

        Ok(PwsafeDb {
            state,
            diff,
            reader,
            path,
            lock,
            userinfo,
        })
    }

    pub fn with_lock<V>(&mut self, f: impl FnOnce(&mut Self) -> Result<V, Report>)
        -> Result<V, Report>
    {
        let _lockfile = LockFile::create(self.lock.clone(), &self.userinfo)?;
        f(self)
    }

    pub fn session(&self) -> Option<Session> {
        todo!()
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

#[derive(Deserialize, Serialize)]
struct State {
    /// An existing matrix session related to this pwsafe-matrix database.
    #[serde(default)]
    session: Option<Session>,
    #[serde(default)]
    room: Option<OwnedRoomId>,
}
