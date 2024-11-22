use crate::ArgsPwsafe;
use crate::pwsafe::PwsafeDb;

use std::path::PathBuf;
use matrix_sdk::ruma::{OwnedDeviceId, OwnedRoomId, OwnedUserId};
use serde::{Deserialize, Serialize};
use eyre::Report;

pub fn run(
    pwsafe: ArgsPwsafe,
    invite: PathBuf,
) -> Result<(), Report> {
    let db = PwsafeDb::open(&pwsafe)?;

    let Some(session) = db.session() else {
        let report = Report::msg("Not a pwsafe-matrix file, use `create` or `join` to link file into a Matrix Room.");
        return Err(report);
    };

    let Some(room) = db.room() else {
        let report = Report::msg("Not a pwsafe-matrix file, use `create` or `join` to link file into a Matrix Room.");
        return Err(report);
    };

    let (stdout, mut lock, mut file);
    let output: &mut dyn std::io::Write = {
        if let Some("-") = invite.to_str() {
            stdout = std::io::stdout();
            lock = stdout.lock();
            &mut lock
        } else {
            file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(invite)?;
            &mut file
        }
    };

    Invite {
        room: room.clone(),
        user: session.meta.user_id.clone(),
        device: session.meta.device_id.clone(),
    }.write(output)?;

    Ok(())
}

#[derive(Deserialize, Serialize)]
pub struct Invite {
    pub room: OwnedRoomId,
    pub user: OwnedUserId,
    pub device: OwnedDeviceId,
}

impl Invite {
    pub fn write(&self, into: &mut dyn std::io::Write) -> Result<(), Report> {
        serde_json::to_writer(into, self)?;
        Ok(())
    }

    pub fn read(from: &mut dyn std::io::Read) -> Result<Self, Report> {
        let this = serde_json::from_reader(from)?;
        Ok(this)
    }
}
