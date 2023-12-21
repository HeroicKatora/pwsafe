use clap::Parser;
use std::ffi::OsString;

fn main() {
    println!("Hello, world!");
}

#[derive(Parser)]
struct ArgsRun {
    #[arg(help = "A pwsafe V3 database")]
    pwsafe: OsString,
    #[arg(short = 'd', long = "key-file")]
    passwd_file: Option<OsString>,
    #[arg(long = "password")]
    passwd: String,
}
