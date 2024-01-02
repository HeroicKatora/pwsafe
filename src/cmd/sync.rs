use crate::{ArgsLogin, ArgsServer, ArgsPwsafe};
use crate::matrix::create_session;
use crate::pwsafe::PwsafeDb;
use crate::server::serve;

use eyre::Report;
use tokio::{
    signal,
    task::JoinSet
};

pub async fn run(
    pwsafe: ArgsPwsafe,
    login: Option<ArgsLogin>,
    server: Option<ArgsServer>,
) -> Result<(), Report> {
    let db = PwsafeDb::open(&pwsafe)?;

    let session = db.session().cloned();
    let mut join_set = JoinSet::<Result<(), Report>>::new();

    if session.is_none() {
        return Err(Report::msg("Pwsafe File does not contain matrix credentials"));
    }

    let cs = create_session(login.as_ref(), session).await?;

    // Setup all the concurrent tasks we have, some of them loop forever, some with cancellation.
    // This is 'first-task-finish' concurrency.
    join_set.spawn(async {
        signal::ctrl_c().await?;
        eprintln!("Ctrl-C received");
        Ok(())
    });

    if let Some(server) = server {
        join_set.spawn(serve(server));
    }

    join_set.join_next().await.unwrap()??;

    // The first finished task aborts the whole thing.
    eprintln!("Shutting down sync");
    join_set.abort_all();
    while let Some(next) = join_set.join_next().await {
        next??;
    }

    Ok(())
}
