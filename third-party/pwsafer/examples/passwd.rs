// An example showing how to change the password of the database.

extern crate pwsafer;

use pwsafer::{PwsafeKey, PwsafeReader, PwsafeWriter};
use std::fs::File;
use std::io::{BufReader, BufWriter};

fn main() {
    let rfilename = "./tests/pwsafe.psafe3";
    let wfilename = "./tests/pwsafe.new.psafe3";

    let rfile = BufReader::new(File::open(rfilename).unwrap());
    let wfile = BufWriter::new(File::create(wfilename).unwrap());

    let mut rdb = PwsafeReader::new(rfile, &PwsafeKey::new(b"password")).unwrap();
    let mut wdb = PwsafeWriter::new(wfile, rdb.get_iter(), &PwsafeKey::new(b"test")).unwrap();

    while let Some((field_type, field_data)) = rdb.read_field().unwrap() {
        wdb.write_field(field_type, &field_data).unwrap();
    }

    wdb.finish().unwrap();
}
