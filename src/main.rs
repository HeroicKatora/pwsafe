use clap::Parser;
use std::ffi::OsString;

pub mod diff;

fn main() {
    let args: Args = Args::parse();
    eprintln!("{args:?}");
}

#[derive(Parser, Debug)]
enum Args {
    Create {
        #[command(flatten)]
        pwsafe: ArgsPwsafe,
    },

    Sync {
        #[command(flatten)]
        pwsafe: ArgsPwsafe,
    }
}

#[derive(Parser, Debug)]
struct ArgsPwsafe {
    #[arg(help = "A pwsafe V3 database")]
    pwsafe: OsString,
    #[arg(short = 'd', long = "key-file")]
    passwd_file: Option<OsString>,
    #[arg(long = "password")]
    passwd: String,
}
