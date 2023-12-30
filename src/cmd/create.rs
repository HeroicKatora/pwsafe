use crate::{ArgsCreateRoom, ArgsLogin, ArgsPwsafe};
use crate::pwsafe::PwsafeDb;

use eyre::Report;

pub fn run(
    pwsafe: ArgsPwsafe,
    login: ArgsLogin,
    room: ArgsCreateRoom,
) -> Result<(), Report> {
    let db = PwsafeDb::open(&pwsafe)?;
    Ok(())
}
