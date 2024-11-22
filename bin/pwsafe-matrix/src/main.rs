/// The command implementations.
mod cmd {
    pub mod create;
    pub mod join;
    pub mod invite;
    pub mod sync;
}

mod communicator;
pub mod diff;
// Not using a crate, we want to mirror the pwsafe functionality here. In particular, exclusive
// flags and the contents should be close to the original if possible.
mod lockfile;
mod matrix;
pub mod pwsafe;
mod server;
mod store;

use std::ffi::OsString;
use std::path::PathBuf;

use clap::Parser;
use tokio::runtime;

fn main() -> Result<(), eyre::Report> {
    let args: Args = Args::parse();

    use tracing_subscriber::prelude::*;

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    match args {
        Args::Create { pwsafe, login, room } => {
            let rt = runtime::Runtime::new()?;
            rt.block_on(cmd::create::run(pwsafe, login, room))?;
            Ok(())
        }
        Args::Join { pwsafe, login, invite } => {
            let rt = runtime::Runtime::new()?;
            rt.block_on(cmd::join::run(pwsafe, login, invite))?;
            Ok(())
        }
        Args::Invite { pwsafe, invite } => {
            cmd::invite::run(pwsafe, invite)?;
            Ok(())
        }
        Args::Sync { pwsafe, login, server } => {
            // We'll try to login via the session stored.
            let rt = runtime::Runtime::new()?;
            rt.block_on(cmd::sync::run(pwsafe, login.into(), server.into()))?;
            Ok(())
        }
    }
}

#[derive(Parser, Debug)]
enum Args {
    Create {
        #[command(flatten)]
        pwsafe: ArgsPwsafe,
        #[command(flatten)]
        login: ArgsLogin,
        #[command(flatten)]
        room: ArgsCreateRoom,
    },

    Join {
        #[command(flatten)]
        pwsafe: ArgsPwsafe,
        #[command(flatten)]
        login: ArgsLogin,
        #[arg(short = 'f', long = "file", help = "An invitation file previously exported with the `invite` command")]
        invite: PathBuf,
    },

    Invite {
        #[command(flatten)]
        pwsafe: ArgsPwsafe,
        #[arg(short = 'f', long = "file", help = "The path to export the invitation file into")]
        invite: PathBuf,
    },

    Sync {
        #[command(flatten)]
        pwsafe: ArgsPwsafe,
        #[command(flatten)]
        login: MaybeLogin,
        #[command(flatten)]
        server: MaybeServer,
    }
}

#[derive(Parser, Debug)]
pub struct ArgsPwsafe {
    #[arg(help = "A pwsafe V3 database")]
    pwsafe: OsString,
    #[arg(short = 'd', long = "key-file")]
    passwd_file: Option<OsString>,
    #[arg(long = "password")]
    passwd: String,
}

#[derive(Parser, Debug)]
pub struct ArgsLogin {
    #[arg(short = 'h', long = "homeserver")]
    homeserver: url::Url,
    #[arg(long = "user")]
    user: String,
    #[arg(long = "matrix-password")]
    password: Option<String>,
    #[arg(long = "no-password-from-tty", default_value_t = false)]
    not_from_tty: bool,
}

#[derive(Parser, Debug)]
#[group(requires_all = ["homeserver", "user"])]
pub struct MaybeLogin {
    #[arg(short = 'h', long = "homeserver")]
    homeserver: Option<url::Url>,
    #[arg(long = "user")]
    user: Option<String>,
    #[arg(long = "matrix-password")]
    password: Option<String>,
    #[arg(long = "no-password-from-tty", default_value_t = false)]
    not_from_tty: bool,
}

#[derive(Parser, Debug)]
pub struct ArgsCreateRoom {
    #[arg(long = "room-alias")]
    alias: Option<String>,
    #[arg(long = "force", default_value_t = false)]
    force: bool,
}

#[derive(Parser, Debug)]
pub struct ArgsServer {
    #[arg(long = "server-http-authorization")]
    secret: String,
    #[arg(long = "server-address")]
    address: std::net::SocketAddr,
    #[arg(long = "server-ready", default_value_t = false)]
    ready: bool,
}

#[derive(Parser, Debug)]
#[group(requires_all = ["address", "secret"])]
pub struct MaybeServer {
    #[arg(long = "server-http-authorization")]
    secret: Option<String>,
    #[arg(long = "server-address")]
    address: Option<std::net::SocketAddr>,
    #[arg(long = "server-ready", default_value_t = false)]
    ready: bool,
}

impl MaybeLogin {
    pub fn into(self) -> Option<ArgsLogin> {
        if self.homeserver.is_some() {
            Some(ArgsLogin {
                homeserver: self.homeserver.unwrap(),
                user: self.user.unwrap(),
                password: self.password,
                not_from_tty: self.not_from_tty,
            })
        } else {
            None
        }
    }
}

impl MaybeServer {
    pub fn into(self) -> Option<ArgsServer> {
        if self.address.is_some() {
            Some(ArgsServer {
                secret: self.secret.unwrap(),
                address: self.address.unwrap(),
                ready: self.ready,
            })
        } else {
            None
        }
    }
}
