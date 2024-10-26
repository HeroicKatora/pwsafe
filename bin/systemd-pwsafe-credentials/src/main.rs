use clap::Parser;
use tokio::net::{
    unix::{gid_t, uid_t, SocketAddr, UCred},
    UnixListener, UnixStream,
};

mod configuration;
mod pwfile;

fn main() {
    let app = App::parse();
    with_io(app).unwrap();
}

#[tokio::main]
async fn with_io(app: App) -> std::io::Result<()> {
    let _ = tokio::fs::remove_file(&app.socket);
    let listener = UnixListener::bind(&app.socket)?;

    let store = pwfile::Passwords::new(app.pwsafe.clone()).await?;
    let reader = store.reader();

    tokio::task::spawn_local(unlock(store));

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
        tokio::task::spawn_local(answer_stream(stream, systemd, reader));
    }
}

async fn unlock(store: pwfile::Passwords) {
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

async fn read_password_from_user() -> std::io::Result<pwsafer::PwsafeKey> {
    todo!()
}

async fn answer_stream(
    mut stream: UnixStream,
    systemd: SystemdUnitSource,
    mut store: pwfile::PasswordReader,
) -> std::io::Result<()> {
    let Ok(unlocked) = store.as_unlocked().await else {
        // Closing down, no more updates!
        return Ok(());
    };

    // Map the requested password to an internal UUID.
    //
    // Then search the password store for the UUID.
    //
    // Then send out the recovered password field entry.

    use tokio::io::AsyncWriteExt as _;
    // FIXME: not the actual password.
    stream.write_all(systemd.credential.as_bytes()).await
    // Closes the stream.
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
    #[arg(long = "no-permission-checks")]
    allow: bool,
    #[arg(default_value = "target/systemd-pwsafe-credentials.sock")]
    socket: std::path::PathBuf,
    #[arg(default_value = "0")]
    uid: uid_t,
    #[arg(default_value = "0")]
    gid: gid_t,
}
