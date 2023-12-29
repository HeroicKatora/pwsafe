use std::ffi::OsString;
use std::path::PathBuf;

use clap::Parser;

pub mod diff;
pub mod pwsafe;

fn main() {
    let args: Args = Args::parse();

    match args {
        Args::Create { pwsafe, login, room } => {
        }
        Args::Join { pwsafe, login, invite } => {
        }
        Args::Invite { pwsafe, invite } => {
        }
        Args::Sync { pwsafe } => {
            // We'll try to login via the session stored first.
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
}

#[derive(Parser, Debug)]
pub struct ArgsCreateRoom {
    #[arg(long = "room-alias")]
    alias: Option<String>,
}
