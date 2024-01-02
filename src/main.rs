/// The command implementations.
mod cmd {
    pub mod create;
    pub mod join;
    pub mod invite;
    pub mod sync;
}

pub mod diff;
// Not using a crate, we want to mirror the pwsafe functionality here. In particular, exclusive
// flags and the contents should be close to the original if possible.
mod lockfile;
mod matrix;
pub mod pwsafe;
mod server;

use std::ffi::OsString;
use std::path::PathBuf;

use clap::Parser;
use tokio::runtime;

fn main() -> Result<(), eyre::Report> {
    let args: Args = Args::parse();

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
            rt.block_on(cmd::sync::run(pwsafe, login, server))?;
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
        login: Option<ArgsLogin>,
        #[command(flatten)]
        server: Option<ArgsServer>,
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
}
