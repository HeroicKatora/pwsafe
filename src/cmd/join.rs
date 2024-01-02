use crate::{ArgsLogin, ArgsPwsafe};
use crate::matrix::create_session;
use crate::cmd::invite::Invite;
use crate::pwsafe::PwsafeDb;

use std::path::PathBuf;
use eyre::Report;

pub async fn run(
    pwsafe: ArgsPwsafe,
    login: ArgsLogin,
    invite: PathBuf,
) -> Result<(), Report> {
    let db = PwsafeDb::open(&pwsafe)?;
    let session = db.session().cloned();

    let cs = create_session(Some(&login), session).await?;

    let (stdin, mut lock, mut file);
    let input: &mut dyn std::io::Read = {
        if let Some("-") = invite.to_str() {
            stdin= std::io::stdin();
            lock = stdin.lock();
            &mut lock
        } else {
            file = std::fs::OpenOptions::new()
                .read(true)
                .open(invite)?;
            &mut file
        }
    };

    let invite = Invite::read(input)?;
    cs.client.join_room_by_id(&invite.room).await?;

    Ok(())
}
