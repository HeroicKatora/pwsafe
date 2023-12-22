//! Create a diff, a local chain of edits, from a previous and new version of a pwsafe file.
use core::ops::Range;
use std::collections::HashMap;
use std::io::Read;

use pwsafer::PwsafeReader;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Default, Clone)]
pub struct DiffableBase {
    pepper: Vec<u8>,
    fields: Vec<FieldMark>,
    entries: HashMap<Uuid, Range<usize>>,
}

pub struct Update {
    pub new_base: DiffableBase,
}

#[derive(Clone, Copy)]
struct FieldMark {
    hash: [u8; 32],
}

pub struct Error {
    inner: Box<dyn core::fmt::Debug + Send + Sync + 'static>,
}

impl DiffableBase {
    pub fn visit(&self, mut reader: PwsafeReader<impl Read>) -> Result<Update, Error> {
        let mut new_base = self.clone();

        Self::fill_entry(&mut reader)?;

        match reader.verify() {
            Err(err) => Err(err)?,
            Ok(()) => Ok(Update {
                new_base,
            })
        }
    }

    fn fill_entry(reader: &mut PwsafeReader<impl Read>) -> Result<(), Error> {
        loop {
            match reader.read_field() {
                Err(err) => return Err(err)?,
                Ok(Some((field, data))) => {
                },
                Ok(None) => {
                    break;
                }
            }
        }

        Ok(())
    }
}

/// Harry-Potter.
impl<E> From<E> for Error
where
    E: core::fmt::Debug + Send + Sync + 'static,
{
    fn from(value: E) -> Self {
        Error {
            inner: Box::new(value),
        }
    }
}
