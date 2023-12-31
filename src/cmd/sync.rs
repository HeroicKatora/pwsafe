use crate::{ArgsCreateRoom, ArgsLogin, ArgsPwsafe};
use crate::matrix::create_session;
use crate::pwsafe::PwsafeDb;

use eyre::Report;

pub async fn run(
    pwsafe: ArgsPwsafe,
    login: Option<ArgsLogin>,
) -> Result<(), Report> {
    let db = PwsafeDb::open(&pwsafe)?;
    let session = db.session().cloned();

    if session.is_none() {
        return Err(Report::msg("Pwsafe File does not contain matrix credentials"));
    }

    let cs = create_session(login.as_ref(), session).await?;

    Ok(())
}
