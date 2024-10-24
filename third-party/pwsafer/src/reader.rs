use block_padding::ZeroPadding;
use byteorder::{LittleEndian, ReadBytesExt};
use hmac::{digest::MacError, Hmac, Mac};
use secrets::SecretVec;
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Read, Seek};
use twofish::cipher::crypto_common::generic_array::GenericArray;
use twofish::cipher::{
    crypto_common::{KeyInit, KeyIvInit},
    BlockDecrypt, BlockDecryptMut,
};
use twofish::Twofish;

use crate::field::PwsafeHeaderField;
use crate::key::PwsafeKey;
use crate::secrets_vec::SecretCursor;

/// A specialized `Result` type for Password Safe database reader.
pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Debug)]
/// Password Safe database reader error.
pub enum Error {
    /// Incorrect file signature, file is not a password safe database.
    InvalidTag,
    /// Invalid password.
    InvalidPassword,
    /// Invalid header (mandatory version field is missing or has wrong length).
    InvalidHeader,
    /// Invalid key for block cipher
    InvalidCipherKey,
    /// An I/O error.
    IoError(io::Error),
    /// HMAC error.
    MacError(MacError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidTag => write!(f, "Not a Password Safe database file"),
            Error::InvalidPassword => write!(f, "Invalid password"),
            Error::InvalidHeader => write!(f, "Invalid header"),
            Error::InvalidCipherKey => write!(f, "Invalid block cipher key"),
            Error::IoError(ref e) => e.fmt(f),
            Error::MacError(ref e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IoError(err)
    }
}

impl From<MacError> for Error {
    fn from(err: MacError) -> Error {
        Error::MacError(err)
    }
}

type TwofishCbc = cbc::Decryptor<Twofish>;
type HmacSha256 = Hmac<Sha256>;

/// Password safe reader.
///
/// ```rust
/// use pwsafer::{PwsafeKey, PwsafeReader};
/// use std::fs::File;
/// use std::io::BufReader;
///
/// let filename = "tests/pwsafe.psafe3";
/// let key = PwsafeKey::new(b"password");
///
/// let file = BufReader::new(File::open(filename).unwrap());
/// let mut db = PwsafeReader::new(file, &key).unwrap();
/// let version = db.read_version().unwrap();
/// println!("Version is {:x}", version);
/// while let Some((field_type, field_data)) = db.read_field() {
///     println!("Read field of type {} and length {}", field_type, field_data.len());
/// }
/// ```
pub struct PwsafeReader<R> {
    inner: R,
    cursor: SecretCursor,
    /// Number of iterations
    iter: u32,
}

struct NextBufferedField<'slice> {
    field_type: u8,
    field_data: &'slice [u8],
    len: usize,
    block_tail: &'slice [u8],
}

impl<R> PwsafeReader<R> {
    const EOF: [u8; 16] = *b"PWS3-EOFPWS3-EOF";

    /// Creates a new `PwsafeReader` with the given password and reads ps3db data into buffer.
    pub fn new(mut inner: R, key: &PwsafeKey) -> Result<Self>
    where
        R: Read,
    {
        let (iter, buffer) = Self::read_from(&mut inner, key)?;

        Ok(PwsafeReader {
            inner,
            cursor: buffer,
            iter,
        })
    }

    /// A database that has not yet been ingested / decrypted.
    pub fn from_locked(inner: R) -> Self {
        PwsafeReader {
            inner,
            cursor: SecretCursor::default(),
            iter: 0,
        }
    }

    fn read_from(inner: &mut R, key: &PwsafeKey) -> Result<(u32, SecretCursor)>
    where
        R: Read,
    {
        let mut tag = [0; 4];
        if inner.read_exact(&mut tag).is_err() {
            return Err(Error::InvalidTag);
        };

        if &tag != b"PWS3" {
            return Err(Error::InvalidTag);
        }

        let mut salt = [0; 32];
        inner.read_exact(&mut salt)?;
        let iter = inner.read_u32::<LittleEndian>()?;
        let mut truehash = [0; 32];
        inner.read_exact(&mut truehash)?;

        let mut k = [0u8; 32];
        let mut l = [0u8; 32];
        let mut iv = [0u8; 16];
        inner.read_exact(&mut k)?;
        inner.read_exact(&mut l)?;
        inner.read_exact(&mut iv)?;

        let twofish_cipher;

        {
            let key = key.hash(&salt, iter);
            let key = key.borrow();

            let mut hasher = Sha256::default();
            hasher.update(&*key);
            if hasher.finalize().as_slice() != truehash {
                return Err(Error::InvalidPassword);
            }

            twofish_cipher = Twofish::new((&*key).into());
        }

        // FIXME: really want to use generic array 1.0 here with slice conversion.
        for ch in k.chunks_exact_mut(16) {
            twofish_cipher.decrypt_block(GenericArray::from_mut_slice(ch));
        }

        for ch in l.chunks_exact_mut(16) {
            twofish_cipher.decrypt_block(GenericArray::from_mut_slice(ch));
        }

        let cbc_cipher = TwofishCbc::new_from_slices(&k, &iv).unwrap();

        let mut buffer = Vec::new();
        inner.read_to_end(&mut buffer)?;

        // 48 because of pws3eof and hmac
        let Some(data_len) = buffer.len().checked_sub(48) else {
            return Err(Error::InvalidTag);
        };

        if data_len % 16 != 0 {
            return Err(Error::InvalidTag);
        };

        let mut secret = SecretVec::<u8>::from(&mut buffer[..]);
        let mut buffer = secret.borrow_mut();

        let (plain_text, tail) = buffer.split_at_mut(data_len);
        // Length checked above to be precisely 48.
        let (eof, inner_mac) = tail.split_at(16);
        let inner_mac: [u8; 32] = inner_mac.try_into().unwrap();

        if eof != Self::EOF {
            return Err(Error::InvalidTag);
        };

        // Do we want to avoid the plain-text representation sitting there?
        // Could incrementally decrypt on read_field and return by reference.
        cbc_cipher
            .decrypt_padded_mut::<ZeroPadding>(plain_text)
            .unwrap();

        let mut hmac: HmacSha256 = Mac::new_from_slice(&l).unwrap();
        // The HMAC is _just_ over the data fields, not their type. A little bit of a weird choice,
        // imho, but it does seems okay.
        let mut field_iteration = &plain_text[..];
        while let Some(field) = Self::next_buffered_field(field_iteration) {
            hmac.update(field.field_data);
            field_iteration = field.block_tail;
        }
        hmac.verify((&inner_mac).into())?;

        drop(buffer);
        let cursor = SecretCursor::from(secret);
        Ok((iter, cursor))
    }

    /// Decrypt the database, reading data from scratch.
    pub fn reread(&mut self, key: &PwsafeKey) -> Result<()>
    where
        R: Read + Seek,
    {
        self.inner.seek(std::io::SeekFrom::Start(0))?;
        let (iter, buffer) = Self::read_from(&mut self.inner, key)?;
        self.iter = iter;
        self.cursor = buffer;

        Ok(())
    }

    /// Discard the decrypted data.
    ///
    /// Before entries can be re-iterated, the data needs to be [`Self::reread`].
    pub fn lock(&mut self) {
        self.cursor = SecretCursor::default();
    }

    /// Reset the reader position of the iterator.
    pub fn restart(&mut self) {
        self.cursor.set_position(0);
    }

    /// Reads the database version field.
    pub fn read_version(&mut self) -> Result<u16> {
        let (field_type, data) = self.read_field().unwrap();
        let field = PwsafeHeaderField::new(field_type, data);
        if let Ok(PwsafeHeaderField::Version(version)) = field {
            return Ok(version);
        }
        Err(Error::InvalidHeader)
    }

    /// Reads a field.
    ///
    /// Returns field type and contents or `None` if EOF block is encountered.
    pub fn read_field(&mut self) -> Option<(u8, Vec<u8>)> {
        self.cursor.with_buf(|tail, consume| {
            let Some(field) = Self::next_buffered_field(tail) else {
                return None;
            };

            let data = field.field_data.to_vec();
            let field_type = field.field_type;
            *consume += field.len;

            Some((field_type, data))
        })
    }

    fn next_buffered_field<'slice>(data: &'slice [u8]) -> Option<NextBufferedField<'slice>> {
        if data.is_empty() {
            return None;
        }

        let header: &[u8; 16] = data[..16].try_into().unwrap();
        if *header == Self::EOF {
            return None;
        }

        let field_length = u32::from_le_bytes(header[..4].try_into().unwrap());
        let field_type = header[4];

        let data_containing_tail = &data[5..];
        let mut block_tail = &data[16..];
        // Size of data not yet in blocks we consumed.
        let mut remaining = field_length;

        // Make sure all variables are in sync, not end up out-of-bounds, and do not wrap.
        while remaining > 11 {
            block_tail = &block_tail[16..];
            remaining = remaining.saturating_sub(16);
        }

        Some(NextBufferedField {
            field_type,
            // Cast is safe, we have already iterated over more of the slice than this length,
            // proving that the slice length bounds it from above.
            field_data: &data_containing_tail[..field_length as usize],
            len: data.len() - block_tail.len(),
            block_tail,
        })
    }

    /// Returns the number of iterations used for key stretching.
    pub fn get_iter(&self) -> u32 {
        self.iter
    }
}
