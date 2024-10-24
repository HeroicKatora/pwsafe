use crate::{reader::PwsafeReader, writer::PwsafeWriter, PwsafeKey};

#[test]
fn roundtrip() {
    let inner = std::io::Cursor::new(vec![0u8; 0]);
    let key = PwsafeKey::new(b"password");

    const DUMMY_FIELD: u8 = 0x42;
    const DUMMY_DATA: &[u8] = b"dummy";

    let mut writer = PwsafeWriter::new(inner, 32, &key).unwrap();
    writer.write_field(DUMMY_FIELD, DUMMY_DATA).unwrap();
    writer.finish().unwrap();

    let (_, mut inner) = writer.take();
    inner.set_position(0);

    let mut reader = PwsafeReader::new(inner, &key).unwrap();
    let (ty, data) = reader.read_field().unwrap().unwrap();

    assert_eq!(ty, DUMMY_FIELD);
    assert_eq!(data, DUMMY_DATA);
}
