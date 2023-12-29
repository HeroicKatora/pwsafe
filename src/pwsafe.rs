use super::ArgsPwsafe;

use eyre::Report;

use matrix_sdk::Session;
use matrix_sdk::ruma::OwnedRoomId;
use pwsafer::PwsafeReader;

use serde::{Serialize, Deserialize};

pub struct PwsafeDb {
    /// Cached version of the state, might be defaulted.
    state: State,
}

impl PwsafeDb {
    pub fn open(args: &ArgsPwsafe) -> Result<Self, Report> {
        let newly_read_passwd;
        let passwd = if let Some(path) = &args.passwd_file {
            newly_read_passwd = std::fs::read(path)?;
            newly_read_passwd.as_slice()
        } else {
            args.passwd.as_bytes()
        };

        let file = std::fs::File::open(&args.pwsafe)?;
        let mut reader = PwsafeReader::new(file, passwd)?;

        todo!()
    }

    pub fn session(&self) -> Option<Session> {
        todo!()
    }

    pub fn set_session(&mut self, session: Session) {
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
