use clap::Parser;
use tokio::net::{
    unix::{gid_t, uid_t, SocketAddr, UCred},
    UnixListener, UnixStream,
};

mod pwfile;

fn main() {
    let app = App::parse();
    with_io(app).unwrap();
}

#[tokio::main]
async fn with_io(app: App) -> std::io::Result<()> {
    let listener = UnixListener::bind(&app.socket)?;

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

        tokio::spawn(answer_stream(stream, systemd));
    }
}

async fn answer_stream(stream: UnixStream, systemd: SystemdUnitSource) -> std::io::Result<()> {
    todo!()
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
    #[arg(long = "no-permission-checks")]
    allow: bool,
    #[arg()]
    socket: std::path::PathBuf,
    #[arg(default_value = "0")]
    uid: uid_t,
    #[arg(default_value = "0")]
    gid: gid_t,
}
