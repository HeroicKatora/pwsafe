use std::{ffi::OsString, sync::Arc};

use clap::Parser;

use pwsafer::PwsafeKey;
use tokio::net::{
    unix::{gid_t, uid_t, UCred},
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

    let ask_pass = {
        // Most specific but very unlikely to exist outright.
        let ours = std::env::var_os("PWSAFE_ASKPASS");
        // Unlikely to exist but we take it.
        let ask = std::env::var_os("ASKPASS");
        // Likely to exist.
        let ssh = std::env::var_os("SSH_ASKPASS");

        ours.or(ask)
            .or(ssh)
            .unwrap_or_else(|| "/usr/lib/ssh/x11-ssh-askpass".into())
    };

    let ask_pass = move || {
        let program = ask_pass.clone();

        async { read_password_ssh_askpass(program).await }
    };

    let cfg = tokio::fs::read_to_string(&app.configuration).await?;
    let cfg = configuration::Configuration::from_str(&cfg)?;
    let cfg = Arc::new(cfg);

    let store = pwfile::Passwords::new(app.pwsafe.clone()).await?;
    let reader = store.reader();

    let local = tokio::task::LocalSet::new();
    local.spawn_local(unlock(store, cfg.clone(), ask_pass));
    local.run_until(listen(app, cfg, listener, reader)).await
}

async fn unlock<WithMethod>(
    store: pwfile::Passwords,
    cfg: Arc<configuration::Configuration>,
    mut read_password_from_user: impl FnMut() -> WithMethod,
) where
    WithMethod: core::future::Future<Output = std::io::Result<pwsafer::PwsafeKey>>,
{
    let rate_limit = std::time::Duration::from_secs_f32(cfg.password_retry);
    let mut frequency = tokio::time::interval(rate_limit);

    let relock_time = std::time::Duration::from_secs_f32(cfg.password_lock);
    let relock_time_sleep = std::time::Duration::from_secs(u32::MAX as u64);
    let mut relock_at = tokio::time::interval(relock_time_sleep);

    loop {
        tokio::select! {
            _ = relock_at.tick() => {
                store.lock();
                relock_at.reset_after(relock_time_sleep);
            },
            Some(req) = store.as_lock_request() => {
                let key = match read_password_from_user().await {
                    Ok(key) => key,
                    Err(_err) => {
                        continue;
                    }
                };

                if let Err(_err) = req.unlock(&key) {
                    eprintln!("This did not unlock!");
                    frequency.reset();
                    frequency.tick().await;
                    continue;
                }

                relock_at.reset_after(relock_time);
            }
        }
    }
}

async fn read_password_ssh_askpass(program: OsString) -> std::io::Result<pwsafer::PwsafeKey> {
    let mut output = tokio::process::Command::new(program)
        .arg(format!("systemd-pwsafe for "))
        .output()
        .await?;
    // Always add a newline.. Hence, I hate using pipes for communicating structured information.
    let _ = output.stdout.pop();
    Ok(PwsafeKey::new(&output.stdout))
}

async fn listen(
    app: App,
    cfg: Arc<configuration::Configuration>,
    listener: UnixListener,
    reader: pwfile::PasswordReader,
) -> std::io::Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        eprintln!("Connection attempt from {peer_addr:?}");

        let Some(systemd) = filter_by_peer_addr(&stream) else {
            eprintln!("Bad peer {peer_addr:?}");
            continue;
        };

        let Ok(cred) = stream.peer_cred() else {
            eprintln!("Invalid peer creds {peer_addr:?}");
            continue;
        };

        if !app.allow && !verify_creds(&app, &cred) {
            eprintln!("Unprivileged peer creds {peer_addr:?}");
            continue;
        };

        let reader = reader.clone();
        let cfg = cfg.clone();
        tokio::task::spawn_local(answer_stream(stream, systemd, reader, cfg));
    }
}

async fn answer_stream(
    mut stream: UnixStream,
    systemd: SystemdUnitSource,
    store: pwfile::PasswordReader,
    app: Arc<configuration::Configuration>,
) -> std::io::Result<()> {
    eprintln!(
        "Serving key from {} for {}",
        systemd.service, systemd.credential
    );

    match answer_request(&systemd, store, app).await? {
        Some(key) => {
            eprintln!("Found valid passphrase for service {}", systemd.service);
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
    systemd: &SystemdUnitSource,
    mut store: pwfile::PasswordReader,
    app: Arc<configuration::Configuration>,
) -> std::io::Result<Option<Vec<u8>>> {
    let Ok(mut unlocked) = store.as_unlocked().await else {
        eprintln!("Store locked and not unlocking");
        // Closing down, no more updates!
        return Ok(None);
    };

    // Map the requested password to an internal UUID.
    let Some(source) = app.credentials.get(&systemd.credential) else {
        eprintln!("Store does not map credential {:?}", systemd.credential);
        return Ok(None);
    };

    // Then search the password store for the UUID.
    match source {
        &configuration::CredentialSource::ByUuid(uuid) => {
            eprintln!("Searching store for UUID {:?}", uuid);
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

fn filter_by_peer_addr(stream: &UnixStream) -> Option<SystemdUnitSource> {
    use std::os::fd::AsRawFd as _;
    let fd = stream.as_raw_fd();

    // The `SocketAddr` we get from tokio only includes `sockaddr_t` information. However we
    // require the whole `sockaddr_un` for the AF_UNIX extras.
    let mut peer = uapi::c::sockaddr_un {
        sun_family: 0,
        sun_path: [0; 108],
    };

    uapi::getpeername(fd, &mut peer).ok()?;
    let path = peer.sun_path.map(|x: core::ffi::c_char| x as u8);
    parse_peer_addr(&path)
}

fn parse_peer_addr(abstract_addr: &[u8]) -> Option<SystemdUnitSource> {
    // "\0adf9d86b6eda275e/unit/foobar.service/credx"
    let (0u8, tail) = abstract_addr.split_first()? else {
        // Not the abstract socket type.
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

    let credential = std::str::from_utf8(credential).ok()?;

    let credential = match credential.split_once('\0') {
        Some((name, _)) => name,
        None => credential,
    };

    Some(SystemdUnitSource {
        service,
        credential: credential.to_owned(),
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
