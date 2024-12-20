use crate::{ArgsLogin, ArgsServer, ArgsPwsafe};
use crate::communicator::{Communicator, Message, Station, SyncPoint, Id};
use crate::matrix::create_session;
use crate::pwsafe::{PwsafeDb, Timestamp};
use crate::server::serve;

use std::collections::{HashMap, VecDeque};
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

    let cs = create_session(login.as_ref(), session, db.store()).await?;
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

    join_set.spawn(refresh(pwsafe.pwsafe.into(), inst_stream.clone()));
    join_set.spawn(sync_on(client.clone(), room, inst_stream));
    join_set.spawn(work_on(station, db));

    join_set.join_next().await.unwrap()??;

    // The first finished task aborts the whole thing.
    tracing::debug!("Shutting down sync");
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
    // FIXME: we can detect file system changes (the removal of the lock-file) to determine an
    // intermediate event for rebase. It only costs energy (processor time and memory) to do this a
    // little too pro-actively. Well, and the lock file can conflict.
    _path: std::path::PathBuf,
    comm: Communicator,
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
        move |event: SyncRoomMessageEvent| {
            let comm = comm.clone();

            async move {
                tracing::debug!("Sync {event:?}");
                let ts = Timestamp {
                    ts_ms: event.origin_server_ts().0.into(),
                    unique: event.event_id().to_string(),
                };

                let val: serde_json::Value = todo!();
                let _ = comm.send_remote(val, ts).await;
            }
        });

    client.sync_with_callback(sync_settings, |_event| async move {
        LoopCtrl::Continue
    }).await?;

    Ok(())
}

async fn work_on(
    mut station: Station,
    mut db: PwsafeDb,
) -> Result<(), Report> {
    const BATCH_SIZE: usize = 16;

    #[derive(Clone, Debug, PartialEq)]
    struct AwaitTs {
        local: u64,
        remote: Option<Timestamp>,
    }

    #[derive(PartialEq)]
    struct UqTs<'st> {
        ts_ms: u64,
        name: &'st str,
    }

    // We do not order events with the same timestamp, but anything with different timestamps.
    impl core::cmp::PartialOrd for AwaitTs {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            const NO_TS: UqTs<'static> = UqTs { ts_ms: 0, name: "" };

            fn uq_ts<'a>(v: &'a Timestamp) -> UqTs<'a> {
                UqTs { ts_ms: v.ts_ms, name: v.unique.as_str() }
            }

            if self == other {
                return Some(core::cmp::Ordering::Equal);
            }

            let this_ts = self.remote.as_ref().map_or(NO_TS, uq_ts);
            let other_ts = other.remote.as_ref().map_or(NO_TS, uq_ts);

            if self.local <= other.local && this_ts <= other_ts {
                Some(core::cmp::Ordering::Less)
            } else if self.local >= other.local && this_ts >= other_ts {
                Some(core::cmp::Ordering::Greater)
            } else {
                None
            }
        }
    }

    impl core::cmp::PartialOrd for UqTs<'_> {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            if self.ts_ms < other.ts_ms {
                Some(core::cmp::Ordering::Less)
            } else if self.ts_ms > other.ts_ms {
                Some(core::cmp::Ordering::Greater)
            } else if self.name == other.name {
                Some(core::cmp::Ordering::Equal)
            } else {
                None
            }
        }
    }

    let mut applied = AwaitTs {
        local: 0,
        remote: None,
    };

    let mut pending = AwaitTs {
        local: 0,
        remote: None,
    };

    let mut acks: HashMap<Id, VecDeque<(AwaitTs, SyncPoint)>>
        = HashMap::default();

    // Only tick so often.. Each tick we apply any number of messages though.
    let mut pacing = time::interval(std::time::Duration::from_micros(50));
    let mut lock_exists = false;

    let mut queue = vec![];

    let mut locals = vec![];
    let mut remotes = vec![];
    let mut remote_ts = vec![];

    loop {
        station.message.recv_many(&mut queue, BATCH_SIZE).await;

        for msg in queue.drain(..) {
            match msg {
                Message::Diff(diff) => {
                    tracing::info!("Local diff received");

                    if let Ok(diff) = db.diff(diff) {
                        locals.push(diff);
                    }
                },
                Message::Remote(diff, ts) => {
                    tracing::info!("Remote diff received {ts:?}");

                    // If we ever receive an invalid diff, it's over!
                    let diff = db.diff(diff)?;

                    debug_assert!(
                        pending.remote.as_ref().map_or(true, |v| v.ts_ms <= ts.ts_ms),
                        "Non-Causal room update: {:?} vs {:?}",
                        pending,
                        ts,
                    );

                    pending.remote = Some(ts.clone());

                    remotes.push(diff);
                    remote_ts.push(ts);
                }
                Message::Sync(id, point) => {
                    tracing::info!("Sync request received {id:?} {point:?}");

                    acks.entry(id).or_default().push_back((pending.clone(), point));
                },
                Message::Rebase => {
                    tracing::info!("Rebase request received");
                    lock_exists = false;
                },
            }
        }

        if !lock_exists {
            // We'd use extract_if here since we want to keep the tail on error. But while that is
            // unstable and Drain's keep_rest was essentially closed we do this trick. Just use the
            // vector itself to keep the rest.
            locals.reverse();

            if let Err(err) = db.with_lock(|mut lock| {
                tracing::info!("Refreshing file");
                lock.refresh()?;
                tracing::info!("Finding new differences added in file");
                lock.push_diff_from_remote()?;

                while let Some(diff) = locals.pop() {
                    tracing::info!("Applying diff {}", applied.local);
                    lock.apply(&diff)?;
                    tracing::info!("Applied diff {}", applied.local);
                    applied.local += 1;
                }

                lock.rebase(&remotes, &remote_ts)?;
                lock.rewrite()?;
                Ok(())
            }) {
                if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
                    if io_err.kind() == std::io::ErrorKind::AlreadyExists {
                        tracing::warn!("Lock already exists: {io_err:?}");
                        lock_exists = true;
                    }
                }

                tracing::warn!("Patch failed: {err:?}");
            } else {
                if let Some(last) = remote_ts.last() {
                    applied.remote = Some(last.clone());
                }

                remotes.clear();
                remote_ts.clear();
            }

            locals.reverse();
        }

        for (id, points) in &mut acks {
            while let Some((need, point)) = points.front() {
                if !(*need < applied) {
                    tracing::debug!("{need:?} {applied:?}");
                    break;
                }

                tracing::info!("Sync request fulfilled {id:?} {point:?}");
                station.ack(*id, *point);
                points.pop_front();
            }
        }

        tokio::task::yield_now().await;
        pacing.tick().await;
    }
}
