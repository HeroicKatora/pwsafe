//! Offers changing the local CRDT state as a server.
//!
//! This must be explicitly requested, usually the editing of the password file will only ever be
//! done by pwsafe itself. The security implications of performing edits directly via the CRDT are
//! absolutely clear. The goal in having this module is for development and testing where a GUI
//! is not robust.
//!
//! Hence, it is absolutely necessary to use a Authorization Bearer token for **all** requests. The
//! token is configured at launch time and should be completely random.
use super::ArgsServer;
use crate::diff::DiffableBase;

use std::sync::Arc;

use axum::{
    extract::{State, Request},
    http::{header::HeaderMap, StatusCode},
    middleware::{from_fn, Next},
    routing::{get, post},
    response::Response,
    Json,
    Router,
};

use eyre::Report;
use serde::Serialize;
use tokio::{net::TcpListener, sync::Notify};

struct AppState {
    authentication_token: String,
    stop: Notify,
}

pub async fn serve(
    server: ArgsServer,
) -> Result<(), Report> {
    if server.secret.len() < 16 {
        return Err(Report::msg("You must configure a stronger authorization secret, at least 16 characters"));
    }

    let state = Arc::new(AppState {
        authentication_token: server.secret,
        stop: Notify::new(),
    });

    let state_auth = state.clone();
    let state_stop = state.clone();

    let app = Router::<Arc<AppState>>::new()
        .route("/health", get(health))
        .route("/stop", post(stop))
        .route("/diff", post(change))
        .layer(from_fn(move |header: HeaderMap, request: Request, next: Next| {
            let auth = state_auth.clone();
            is_authorized(auth, header, request, next)
        }))
        .with_state(state);

    let listener = TcpListener::bind(&server.address).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            state_stop.stop.notified();
        })
        .await?;

    Ok(())
}

async fn health() -> Json<Health> {
    Json(Health { })
}

// FIXME: define a serialized form for Diff, which does not depend upon the client knowing the
// pepper and other internal state. We need that for the CRDT as well, so define it in `Diff`.
async fn change(
    state: State<Arc<AppState>>,
    Json(change): Json<serde_json::Value>,
) {
    let diff: &DiffableBase = todo!();
    match diff.deserialize(change) {
        Ok(change) => {
        },
        Err(err) => {
            todo!("{err:?}")
        },
    }
}

async fn stop(state: State<Arc<AppState>>) {
    state.stop.notify_waiters();
}

#[derive(Serialize)]
struct Health {
}

async fn is_authorized(
    state: Arc<AppState>,
    header: HeaderMap,
    request: Request,
    next: Next,
)
    -> Result<Response, StatusCode>
{
    let authorization = header.get("Authorization")
        .map(|v| v.as_bytes());

    if authorization == Some(state.authentication_token.as_bytes()) {
        Ok(next.run(request).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
