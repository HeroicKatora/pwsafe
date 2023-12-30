use crate::{ArgsLogin, ArgsPwsafe};
use crate::pwsafe::PwsafeDb;

use std::path::PathBuf;
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

    Ok(())
}
