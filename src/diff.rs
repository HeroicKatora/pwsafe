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
use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::io::{Read, Write};

use eyre::Report;
use pwsafer::{PwsafeReader, PwsafeHeaderField, PwsafeRecordField, PwsafeWriter};
use serde::{Deserialize, Serialize};
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
    raw_ty: u8,
    raw_data: Vec<u8>,
    mark: FieldMark,
}

#[derive(Clone)] // Represents an empty diff.
pub struct Diff {
    pub pepper: Box<[u8; 16]>,
    pub delete: HashSet<Uuid>,
    pub edit: HashMap<Uuid, DiffEdit>,
}

/// One specific edit applied to a DB record.
#[derive(Default, Clone)] // Represents an empty diff.
pub struct DiffEdit {
    set: HashMap<u8, Vec<u8>>,
    delete: HashSet<u8>,
}

#[derive(Deserialize, Serialize)]
struct DiffSerial {
    pub delete: HashSet<Uuid>,
    pub edit: HashMap<Uuid, DiffEditSerial>,
}

#[derive(Deserialize, Serialize)]
struct DiffEditSerial {
    set: HashMap<u8, Vec<u8>>,
    delete: HashSet<u8>,
}

pub struct Update {
    pub new_base: DiffableBase,
    pub diff: Diff,
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
    ///
    /// ```
    /// $ uuidgen --name "https://github.com/HeroicKatora/pwsafe-matrix" -n "@dns" --sha1
    /// f8052080-99ed-53ef-8f44-ae5621b31f46
    /// ```
    ///
    /// Exists for mostly documentation purposes, we do not derive from this at runtime.
    #[allow(dead_code)]
    const BASE_UUID: Uuid = Uuid::from_bytes(*b"\xf8\x05\x20\x80\
                                             \x99\xed\
                                             \x53\xef\
                                             \x8f\x44\
                                             \xae\x56\x21\xb3\x1f\x46");

    /// This UUID identifies the entry containing the V1 state of our CRDT.
    /// ```
    /// $ uuidgen --name "pwsafe-matrix-crdt-v1" -n "f8052080-99ed-53ef-8f44-ae5621b31f46" --sha1
    /// 02e4d75b-5fde-582e-b10d-409f041c3d34
    /// ```
    ///
    /// Might switch to const-derivation from `BASE_UUID` at a later point.
    const CRDT_STATE: Uuid = Uuid::from_bytes(*b"\x02\xe4\xd7\x5b\
                                              \x5f\xde\
                                              \x58\x2e\
                                              \xb1\x0d\
                                              \x40\x9f\x04\x1c\x3d\x34");

    pub fn visit(&self, reader: &mut PwsafeReader<impl Read>) -> Result<Update, Report> {
        reader.restart();

        let mut new_base = self.clone();
        Self::skip_header(reader, |_, _| Ok::<_, Report>(()))?;

        let mut entry = RecordDescriptor::default();
        let mut state_record = RecordDescriptor::default();

        let mut prior_keys: HashSet<_> = new_base.entries.keys().cloned().collect();
        prior_keys.remove(&Self::CRDT_STATE);

        let mut diff = Diff::empty(self);

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

        // We've removed all entries that are still present. Everything not removed has been
        // deleted in the new version of the DB.
        diff.delete.extend(prior_keys);

        if !entry.fields.is_empty() {
            return Err(eyre::Report::msg("Database contains record without mandatory UUID field"))?;
        }

        Ok(Update {
            new_base,
            diff,
            state_record,
        })
    }

    pub fn deserialize(&self, edit: serde_json::Value) -> Result<Diff, Report> {
        let inner: DiffSerial = serde_json::from_value(edit)?;

        Ok(Diff {
            pepper: self.pepper.clone(),
            delete: inner.delete,
            edit: inner.edit
                .into_iter()
                .map(|(uuid, e)| {
                    let e = DiffEdit {
                        set: e.set
                            .into_iter()
                            .collect(),
                        delete: e.delete,
                    };

                    (uuid, e)
                })
                .collect(),
        })
    }

    fn skip_header<E>(
        reader: &mut PwsafeReader<impl Read>,
        mut with: impl FnMut(u8, &[u8]) -> Result<(), E>,
    ) -> Result<(), Report>
        where Report: From<E>,
    {
        while let Some((ty, data)) = reader.read_field()? {
            with(ty, &data)?;

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
                    let record = PwsafeRecordField::new(field, data.clone())?;

                    if let &PwsafeRecordField::Uuid(uuid) = &record {
                        field_uuid = Some(Uuid::from_bytes(uuid));
                    }

                    let eof = matches!(record, PwsafeRecordField::EndOfRecord);

                    entry.fields.push(Field {
                        pwsafe: record,
                        raw_ty: field,
                        raw_data: data,
                        mark,
                    });

                    if eof {
                        break;
                    }
                },
                Ok(None) => {
                    break;
                }
            }
        }

        Ok(field_uuid)
    }
}

impl Diff {
    pub fn empty(base: &DiffableBase) -> Self {
        Diff {
            pepper: base.pepper.clone(),
            delete: Default::default(),
            edit: Default::default(),
        }
    }

    pub fn add_state(&mut self, state: String) {
        let edit = self.edit
            .entry(DiffableBase::CRDT_STATE)
            .or_default();

        edit.set.insert(0x05, state.into_bytes());
    }

    pub fn apply(
        &self,
        reader: &mut PwsafeReader<impl Read>,
        writer: &mut PwsafeWriter<impl Write>,
    ) -> Result<(), Report> {
        reader.restart();

        DiffableBase::skip_header(reader, |ty, data| {
            writer.write_field(ty, data)
        })?;

        let mut entry = RecordDescriptor::default();
        let mut edits = self.edit.clone();

        while let Some(uuid) = DiffableBase::fill_entry(reader, &mut entry, &self.pepper)? {
            if self.delete.contains(&uuid) {
                continue;
            }

            let Some(mut edit) = edits.remove(&uuid) else {
                for field in &entry.fields {
                    writer.write_field(field.raw_ty, &field.raw_data)?;
                }

                continue;
            };

            for field in &entry.fields {
                if edit.delete.contains(&field.raw_ty) {
                    continue;
                }

                let data = edit.set.remove(&field.raw_ty);
                let data = data.as_ref().unwrap_or(&field.raw_data);

                writer.write_field(field.raw_ty, data)?;
            }

            for (raw_ty, raw_data) in edit.set {
                writer.write_field(raw_ty, &raw_data)?;
            }
        }

        for (uuid, remote_missing) in edits {
            writer.write_field(0x01, uuid.as_bytes())?;
            for (raw_ty, raw_data) in remote_missing.set {
                writer.write_field(raw_ty, &raw_data)?;
            }
        }

        Ok(())
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
