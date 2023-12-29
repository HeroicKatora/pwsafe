//! Create a diff, a local chain of edits, from a previous and new version of a pwsafe file.
//!
//! The CRDT works as follows: each change has a definitive timestamps the message communicating
//! the diff. This is assigned by the associated homeserver. (So, for one homeserver it doesn't
//! behave as much like a parallel CRDT but oh well). The full history of changes ordered by these
//! timestamps defines the shared, remote state. On top of this remote state, a local set of
//! changes can be applied which will be treated as always being ordered after all remote changes.
//!
//! The two operations to communicate state:
//! - Consuming remote changes, which are applied to the shared state (and then we recover the new
//!   local state by also applying the local changes as if *after* the remote timestamp).
//! - Publishing local changes, atomically diffs the local state against the shared state and
//!   pushes that changeset into the homeserver. The latter operation empties the local changeset
//!   so that the new state after the transaction consists precisely of the shared state.
//!
//!   Since publishing changes to the homeserver might fail, this one will is tricky to do
//!   atomically.
use core::ops::Range;
use std::collections::{HashMap, hash_map::Entry};
use std::io::Read;

use eyre::Report;
use pwsafer::{PwsafeReader, PwsafeHeaderField, PwsafeRecordField};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Default, Clone)]
pub struct DiffableBase {
    pepper: Box<[u8; 16]>,
    fields: Vec<FieldMark>,
    entries: HashMap<Uuid, Range<usize>>,
}

#[derive(Default)]
pub struct RecordDescriptor {
    pub uuid: Uuid,
    pub fields: Vec<Field>,
}

pub struct Field {
    pub pwsafe: PwsafeRecordField,
    mark: FieldMark,
}

pub struct Update {
    pub new_base: DiffableBase,
    /// The internal state record.
    ///
    /// This record is ignored by the diff algorithm itself, but consumed by the loader of the
    /// program and any part restoring the encoded state from the fields contained in it.
    pub state_record: RecordDescriptor,
}

#[derive(Clone, Copy)]
struct FieldMark {
    hash: [u8; 32],
}

impl DiffableBase {
    /// This UUID is associated with the project, as a namespace UUID for UUIDv5.
    // ```
    // $ uuidgen --name "https://github.com/HeroicKatora/pwsafe-matrix" -n "@dns" --sha1
    // f8052080-99ed-53ef-8f44-ae5621b31f46
    // ```
    const BASE_UUID: Uuid = Uuid::from_bytes(*b"\xf8\x05\x20\x80\
                                             \x99\xed\
                                             \x53\xef\
                                             \x8f\x44\
                                             \xae\x56\x21\xb3\x1f\x46");

    /// This UUID identifies the entry containing the V1 state of our CRDT.
    // ```
    // $ uuidgen --name "pwsafe-matrix-crdt-v1" -n "f8052080-99ed-53ef-8f44-ae5621b31f46" --sha1
    // 02e4d75b-5fde-582e-b10d-409f041c3d34
    // ```
    const CRDT_STATE: Uuid = Uuid::from_bytes(*b"\x02\xe4\xd7\x5b\
                                              \x5f\xde\
                                              \x58\x2e\
                                              \xb1\x0d\
                                              \x40\x9f\x04\x1c\x3d\x34");

    pub fn visit(&self, reader: &mut PwsafeReader<impl Read>) -> Result<Update, Report> {
        reader.restart();

        let mut new_base = self.clone();
        Self::skip_header(reader)?;

        let mut entry = RecordDescriptor::default();
        let mut state_record = RecordDescriptor::default();

        while let Some(uuid) = Self::fill_entry(reader, &mut entry, &new_base.pepper)? {
            // We do not diff the UUID state itself.
            if uuid == Self::CRDT_STATE {
                core::mem::swap(&mut state_record, &mut entry);
                continue;
            }

            match new_base.entries.entry(uuid) {
                Entry::Occupied(_) => {
                    todo!();
                },
                Entry::Vacant(vacant) => {
                    let start = new_base.fields.len();
                    new_base.fields.extend(entry.fields.iter().map(|f| f.mark));
                    let end = new_base.fields.len();
                    vacant.insert(start..end);
                },
            }
        };

        if !entry.fields.is_empty() {
            return Err(eyre::Report::msg("Database contains record without mandatory UUID field"))?;
        }

        Ok(Update {
            new_base,
            state_record,
        })
    }

    fn skip_header(
        reader: &mut PwsafeReader<impl Read>
    ) -> Result<(), Report> {
        while let Some((ty, data)) = reader.read_field()? {
            let field = PwsafeHeaderField::new(ty, data)?;
            if matches!(field, PwsafeHeaderField::EndOfHeader) {
                break;
            }
        }

        Ok(())
    }

    fn fill_entry(
        reader: &mut PwsafeReader<impl Read>,
        entry: &mut RecordDescriptor,
        pepper: &[u8; 16],
    ) -> Result<Option<Uuid>, Report> {
        let mut field_uuid = None;
        *entry = RecordDescriptor::default();

        loop {
            match reader.read_field() {
                Err(err) => return Err(err)?,
                Ok(Some((field, data))) => {
                    let mark = FieldMark::new(field, &data, pepper);
                    let record = PwsafeRecordField::new(field, data)?;

                    if let &PwsafeRecordField::Uuid(uuid) = &record {
                        field_uuid = Some(Uuid::from_bytes(uuid));
                    }

                    entry.fields.push(Field {
                        pwsafe: record,
                        mark,
                    });
                },
                Ok(None) => {
                    break;
                }
            }
        }

        Ok(field_uuid)
    }
}

impl FieldMark {
    fn new(ty: u8, data: &[u8], pepper: &[u8; 16]) -> Self {
        let mut digest = Sha256::new();
        digest.update(pepper);
        digest.update(b"\x00");
        digest.update(ty.to_be_bytes());
        digest.update(b"\x01");
        digest.update(data);
        let hash = digest.finalize().into();

        FieldMark { hash }
    }
}
