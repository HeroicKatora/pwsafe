use std::sync::Arc;

use clap::Parser;

use tokio::net::{
    unix::{gid_t, uid_t, SocketAddr, UCred},
    UnixListener, UnixStream,
};

mod configuration;
mod pwfile;
#[cfg(test)]
mod tests;

fn main() {
    let app = App::parse();
    with_io(app).unwrap();
}

#[tokio::main]
async fn with_io(app: App) -> std::io::Result<()> {
    let _ = tokio::fs::remove_file(&app.socket);
    let listener = UnixListener::bind(&app.socket)?;

    let cfg = tokio::fs::read_to_string(&app.configuration).await?;
    let cfg = configuration::Configuration::from_str(&cfg)?;
    let cfg = Arc::new(cfg);

    let store = pwfile::Passwords::new(app.pwsafe.clone()).await?;
    let reader = store.reader();

    tokio::task::spawn_local(unlock(store, read_password_ssh_askpass));

    loop {
        let (stream, peer_addr) = listener.accept().await?;

        let Some(systemd) = filter_by_peer_addr(&peer_addr) else {
            continue;
        };

        let Ok(cred) = stream.peer_cred() else {
            continue;
        };

        if !app.allow && !verify_creds(&app, &cred) {
            continue;
        };

        let reader = reader.clone();
        let cfg = cfg.clone();

        tokio::task::spawn_local(answer_stream(stream, systemd, reader, cfg));
    }
}

async fn unlock<WithMethod>(
    store: pwfile::Passwords,
    mut read_password_from_user: impl FnMut() -> WithMethod,
) where
    WithMethod: core::future::Future<Output = std::io::Result<pwsafer::PwsafeKey>>,
{
    loop {
        if let Some(req) = store.as_lock_request().await {
            let key = match read_password_from_user().await {
                Ok(key) => key,
                Err(_err) => {
                    continue;
                }
            };

            if let Err(_err) = req.unlock(&key) {
                continue;
            }
        }
    }
}

async fn read_password_ssh_askpass() -> std::io::Result<pwsafer::PwsafeKey> {
    todo!()
}

async fn answer_stream(
    mut stream: UnixStream,
    systemd: SystemdUnitSource,
    store: pwfile::PasswordReader,
    app: Arc<configuration::Configuration>,
) -> std::io::Result<()> {
    match answer_request(systemd, store, app).await? {
        Some(key) => {
            // Then send out the recovered password field entry.
            use tokio::io::AsyncWriteExt as _;
            // FIXME: not the actual password.
            stream.write_all(&key).await
            // Closes the stream.
        }
        _ => return Ok(()),
    }
}

async fn answer_request(
    systemd: SystemdUnitSource,
    mut store: pwfile::PasswordReader,
    app: Arc<configuration::Configuration>,
) -> std::io::Result<Option<Vec<u8>>> {
    let Ok(mut unlocked) = store.as_unlocked().await else {
        // Closing down, no more updates!
        return Ok(None);
    };

    // Map the requested password to an internal UUID.
    let Some(source) = app.credentials.get(&systemd.credential) else {
        return Ok(None);
    };

    // Then search the password store for the UUID.
    match source {
        &configuration::CredentialSource::ByUuid(uuid) => {
            // Hm, no. Really this is a failure of the configuration? Should tell.
            Ok(unlocked.search_by_uuid(uuid))
        }
    }
}

struct SystemdUnitSource {
    service: String,
    /// ASCII, really.
    credential: String,
}

fn filter_by_peer_addr(addr: &SocketAddr) -> Option<SystemdUnitSource> {
    let path = addr.as_pathname()?;
    let bytes = path.as_os_str().as_encoded_bytes();

    // "\0adf9d86b6eda275e/unit/foobar.service/credx"
    let (0u8, tail) = bytes.split_first()? else {
        return None;
    };

    let mut parts = tail.split(|&x| x == b'/');
    let random = parts.next()?;
    let unit = parts.next()?;
    let service = parts.next()?;
    let credential = parts.next()?;

    if parts.next().is_some() {
        return None;
    }

    if !random.is_ascii() {
        return None;
    }

    if unit != b"unit" {
        return None;
    }

    let service = std::str::from_utf8(service).ok()?.to_owned();

    if !credential.is_ascii() {
        return None;
    }

    let credential = std::str::from_utf8(credential).ok()?.to_owned();

    Some(SystemdUnitSource {
        service,
        credential,
    })
}

fn verify_creds(app: &App, cred: &UCred) -> bool {
    cred.uid() == app.uid && cred.gid() == app.gid
}

#[derive(Parser)]
pub struct App {
    pwsafe: std::path::PathBuf,
    #[arg(long = "configuration")]
    configuration: std::path::PathBuf,
    #[arg(long = "no-permission-checks")]
    allow: bool,
    #[arg(default_value = "target/systemd-pwsafe-credentials.sock")]
    socket: std::path::PathBuf,
    #[arg(default_value = "0")]
    uid: uid_t,
    #[arg(default_value = "0")]
    gid: gid_t,
}
