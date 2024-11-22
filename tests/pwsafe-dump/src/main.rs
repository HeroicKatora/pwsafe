//! Dump a password safe file to json.
//!
//! This program returns `0` when the file is valid and fully understood. Avoid running it on
//! sensitive data, the data being decrypted is not kept safe at all.
use std::{ffi::OsString, fs};

use color_eyre::eyre::Error;
use pwsafer::{PwsafeReader, PwsafeHeaderField, PwsafeRecordField, PwsafeKey};
use clap::Parser;

fn main() -> Result<(), Error> {
    let args: Args = Args::parse();
    let file = fs::File::open(&args.pwsafe)?;

    let passphrase = match (args.passwd_file, args.passwd) {
        (Some(file), None) => {
            let data = fs::read(file)?;
            PwsafeKey::new(&data)
        },
        (None, Some(string)) => {
            let data = string.as_bytes();
            PwsafeKey::new(data)
        },
        _ => {
            return Err(Error::msg("Provide exactly one of key-file or password"));
        },
    };

    type Printer = dyn FnMut(u8, Vec<u8>) -> bool;

    let mut handle_header = |field: u8, data: Vec<u8>| -> bool {
        let Ok(header) = PwsafeHeaderField::new(field, data) else {
            panic!("Bad header field: {field}");
        };

        eprintln!("{header:?}");
        matches!(header, PwsafeHeaderField::EndOfHeader)
    };

    let mut handle_record = |field: u8, data: Vec<u8>| {
        let Ok(header) = PwsafeRecordField::new(field, data) else {
            panic!("Bad header field: {field}");
        };

        eprintln!("{header:?}");
        false
    };

    let mut handle_field: &mut Printer;
    let handlers: [&mut Printer; 2] = [&mut handle_header, &mut handle_record];
    let mut handlers = handlers.into_iter();

    handle_field = handlers.next().unwrap();
    let mut reader = PwsafeReader::new(file, &passphrase)?;
    while let Some((field, data)) = reader.read_field() {
        if handle_field(field, data) {
            handle_field = handlers.next().unwrap();
        }
    }

    Ok(())
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(help = "A pwsafe V3 database")]
    pwsafe: OsString,
    #[arg(short = 'd', long = "key-file")]
    passwd_file: Option<OsString>,
    #[arg(long = "password")]
    passwd: Option<String>,
}
