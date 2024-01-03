use crate::{ArgsLogin, ArgsServer, ArgsPwsafe};
use crate::communicator::{Communicator, Message, Station};
use crate::matrix::create_session;
use crate::pwsafe::PwsafeDb;
use crate::server::serve;

use std::sync::Arc;
use eyre::Report;
use matrix_sdk::{
    Client,
    LoopCtrl,
    config::SyncSettings,
    ruma::{
        events::room::message::SyncRoomMessageEvent,
        OwnedRoomId,
    },
};
use tokio::{
    signal,
    time,
    task::JoinSet,
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

    let Some(room) = db.room().cloned() else {
        return Err(Report::msg("Pwsafe File does not contain matrix room"));
    };

    let cs = create_session(login.as_ref(), session).await?;
    let client = Arc::new(cs.client);

    // Setup all the concurrent tasks we have, some of them loop forever, some with cancellation.
    // This is 'first-task-finish' concurrency.
    join_set.spawn(async {
        signal::ctrl_c().await?;
        eprintln!("Ctrl-C received");
        Ok(())
    });

    let (inst_stream, station) = Station::new();
    if let Some(server) = server {
        let inst_stream = inst_stream.clone();
        join_set.spawn(serve(server, inst_stream));
    }

    join_set.spawn(sync_on(client.clone(), room, inst_stream));
    join_set.spawn(work_on(client, station));

    join_set.join_next().await.unwrap()??;

    // The first finished task aborts the whole thing.
    eprintln!("Shutting down sync");
    join_set.abort_all();

    while let Some(next) = join_set.join_next().await {
        match next {
            Ok(task) => task?,
            Err(err) if err.is_cancelled() => {},
            Err(err) => Err(err)?,
        }
    }

    Ok(())
}

async fn refresh(
    comm: Communicator,
    // FIXME: we can detect file system changes (the removal of the lock-file) to determine an
    // intermediate event for rebase. It only costs energy (processor time and memory) to do this a
    // little too pro-actively. Well, and the lock file can conflict.
    _path: std::path::PathBuf,
) -> Result<(), Report> {
    let mut time = time::interval(std::time::Duration::from_secs(10));

    loop {
        comm.rebase().await?;
        time.tick().await;
    }
}

async fn sync_on(
    client: Arc<Client>,
    room_id: OwnedRoomId,
    comm: Communicator,
) -> Result<(), Report> {
    let sync_settings = SyncSettings::new()
        .timeout(std::time::Duration::from_secs(30));

    client.add_room_event_handler(
        &room_id,
        |event: SyncRoomMessageEvent| async move {
            eprintln!("Sync {event:?}");
        });

    client.sync_with_callback(sync_settings, |_event| async move {
        LoopCtrl::Continue
    }).await?;

    Ok(())
}

async fn work_on(
    client: Arc<Client>,
    mut station: Station,
    mut db: PwsafeDb,
) -> Result<(), Report> {
    const BATCH_SIZE: usize = 16;

    let mut queue = vec![];
    let mut remotes = vec![];
    let mut remote_ts = vec![];

    loop {
        station.message.recv_many(&mut queue, BATCH_SIZE).await;

        for msg in queue.drain(..) {
            match msg {
                Message::Diff(diff) => {
                    if let Ok(diff) = db.diff(diff) {
                    }
                },
                Message::Remote(diff, ts) => {
                    // If we ever receive an invalid diff, it's over!
                    let diff = db.diff(diff)?;

                    remotes.push(diff);
                    remote_ts.push(ts);
                }
                Message::Sync(id, point) => {
                    // Very incorrect, we did not actually wait until the diffs are all applied.
                    station.ack(id, point);
                },
                Message::Rebase => {
                    if let Err(err) = db.with_lock(|mut lock| {
                        lock.rebase(&remotes, &remote_ts)
                    }) {
                        eprintln!("{err:?}");
                    } else {
                        remotes.clear();
                        remote_ts.clear();
                    }
                },
            }
        }

        tokio::task::yield_now().await;
    }
}
