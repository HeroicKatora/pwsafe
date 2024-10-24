// An example showing how to parse Password Safe database content.
//
// Run as: cargo run --example dump ~/.pwsafe/pwsafe.psafe3 password

use pwsafer::{PwsafeHeaderField, PwsafeKey, PwsafeReader, PwsafeRecordField};
use std::env;
use std::fs::File;
use std::io::BufReader;

fn main() {
    let args: Vec<String> = env::args().collect();
    let filename = &args[1];
    let password = &args[2];

    let file = BufReader::new(File::open(filename).unwrap());
    let key = PwsafeKey::new(password.as_bytes());
    let mut db = PwsafeReader::new(file, &key).unwrap();
    db.read_version().unwrap();

    loop {
        let (field_type, field_data) = db.read_field().unwrap();
        let field = PwsafeHeaderField::new(field_type, field_data);
        println!("{:?}", field);
        if field_type == 0xff {
            break;
        }
    }

    while let Some((field_type, field_data)) = db.read_field() {
        let field = PwsafeRecordField::new(field_type, field_data);
        println!("{:?}", field);
    }
}
