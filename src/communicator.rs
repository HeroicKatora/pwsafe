//! A single task is responsible for modifying the `PasswordDb`, under lock. All other tasks
//! produce streams of instructions with this module defining the communication and acknowledgement
//! scheme.
use core::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::sync::Arc;
use eyre::Report;
use tokio::sync::{mpsc, watch};

use crate::pwsafe::Timestamp;

pub struct Station {
    pub(crate) message: mpsc::Receiver<Message>,
    pub(crate) state: watch::Sender<State>,
    pub(crate) id_gen: Arc<AtomicU64>,
}

pub struct Communicator {
    id_gen: Arc<AtomicU64>,
    id: Id,
    sync_point_next: AtomicU64,
    stream: mpsc::Sender<Message>,
    state: watch::Receiver<State>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[repr(transparent)]
pub(crate) struct Id(u64);

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[repr(transparent)]
pub(crate) struct SyncPoint(u64);

#[derive(Default)]
pub(crate) struct State {
    ack: HashMap<Id, SyncPoint>,
    err_count: AtomicU64,
}

pub(crate) enum Message {
    Diff(serde_json::Value),
    Sync(Id, SyncPoint),
    Remote(serde_json::Value, Timestamp),
    Rebase,
}

impl Station {
    pub fn new() -> (Communicator, Self) {
        let (stream, message) = mpsc::channel(1 << 10);
        let (state, state_recv) = watch::channel(State::default());

        let id_gen = Arc::new(AtomicU64::new(1));
        let station = Station {
            message,
            state,
            id_gen,
        };

        let communicator = Communicator {
            id_gen: station.id_gen.clone(),
            id: Id(0),
            sync_point_next: AtomicU64::new(0),
            stream,
            state: state_recv,
        };

        (communicator, station)
    }

    pub(crate) fn ack(&mut self, id: Id, point: SyncPoint) {
        self.state.send_modify(|state| {
            state.ack.insert(id, point);
        })
    }
}

impl Communicator {
    pub async fn send_diff(&self, diff: serde_json::Value) -> Result<(), Report> {
        self.stream.send(Message::Diff(diff)).await?;
        self._sync().await?;
        Ok(())
    }

    pub async fn send_remote(&self, diff: serde_json::Value, ts: Timestamp) -> Result<(), Report> {
        self.stream.send(Message::Remote(diff, ts)).await?;
        self._sync().await?;
        Ok(())
    }

    pub async fn rebase(&self) -> Result<(), Report> {
        self.stream.send(Message::Rebase).await?;
        self._sync().await?;
        Ok(())
    }

    async fn _sync(&self) -> Result<(), Report> {
        let sync_id = self.sync_point_next.fetch_add(1, Ordering::Relaxed);
        self.stream.send(Message::Sync(self.id, SyncPoint(sync_id))).await?;

        let mut state = self.state.clone();
        state.wait_for(|state| {
            if let Some(sync) = state.ack.get(&self.id) {
                sync_id.wrapping_sub(sync.0) < i64::MAX as u64
            } else {
                false
            }
        }).await?;

        Ok(())
    }
}

impl Clone for Communicator {
    fn clone(&self) -> Self {
        let new_id = self.id_gen.fetch_add(1, Ordering::Relaxed);
        Communicator {
            id_gen: self.id_gen.clone(),
            id: Id(new_id),
            sync_point_next: AtomicU64::new(0),
            stream: self.stream.clone(),
            state: self.state.clone(),
        }
    }
}
