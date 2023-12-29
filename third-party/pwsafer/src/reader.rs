use block_modes::block_padding::ZeroPadding;
use block_modes::{BlockMode, Cbc, Ecb};
use block_modes::cipher::NewBlockCipher;
use byteorder::{LittleEndian, ReadBytesExt};
use hmac::{crypto_mac, Hmac, Mac, NewMac};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Cursor, Read, BufRead};
use twofish::Twofish;

use crate::field::PwsafeHeaderField;
use crate::key::hash_password;

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
    MacError(crypto_mac::MacError),
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

impl From<crypto_mac::MacError> for Error {
    fn from(err: crypto_mac::MacError) -> Error {
        Error::MacError(err)
    }
}

type TwofishCbc = Cbc<Twofish, ZeroPadding>;
type HmacSha256 = Hmac<Sha256>;

/// Password safe reader.
///
/// ```rust
/// use pwsafe::PwsafeReader;
/// use std::fs::File;
/// use std::io::BufReader;
///
/// let filename = "tests/pwsafe.psafe3";
/// let file = BufReader::new(File::open(filename).unwrap());
/// let mut db = PwsafeReader::new(file, b"password").unwrap();
/// let version = db.read_version().unwrap();
/// println!("Version is {:x}", version);
/// while let Some((field_type, field_data)) = db.read_field().unwrap() {
///     println!("Read field of type {} and length {}", field_type, field_data.len());
/// }
/// db.verify().unwrap();
/// ```
pub struct PwsafeReader<R> {
    _inner: R,
    buffer: Cursor<Vec<u8>>,
    /// Number of iterations
    iter: u32,
}

struct NextBufferedField<'slice> {
    field_type: u8,
    field_data: &'slice [u8],
    len: usize,
    block_tail: &'slice [u8],
}

impl<R: Read> PwsafeReader<R> {
    const EOF: [u8; 16] = *b"PWS3-EOFPWS3-EOF";

    /// Creates a new `PwsafeReader` with the given password and reads ps3db data into buffer.
    pub fn new(mut inner: R, password: &[u8]) -> Result<Self> {
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

        let key = hash_password(&salt, iter, password);

        let mut hasher = Sha256::default();
        hasher.update(&key);
        if hasher.finalize().as_slice() != truehash {
            return Err(Error::InvalidPassword);
        }
        
        let twofish_cipher = Twofish::new_from_slice(&key).unwrap();
        let mut ecb_cipher = Ecb::<&Twofish, ZeroPadding>::new(&twofish_cipher, &Default::default());
        ecb_cipher.decrypt(&mut k).unwrap();
        ecb_cipher = Ecb::<&Twofish, ZeroPadding>::new(&twofish_cipher, &Default::default());
        ecb_cipher.decrypt(&mut l).unwrap();

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

        let (plain_text, tail) = buffer.split_at_mut(data_len);
        // Length checked above to be precisely 48.
        let (eof, inner_mac) = tail.split_at(16);
        let inner_mac: [u8; 32] = inner_mac.try_into().unwrap();

        if eof != Self::EOF {
            return Err(Error::InvalidTag);
        };

        // Do we want to avoid the plain-text representation sitting there?
        // Could incrementally decrypt on read_field and return by reference.
        cbc_cipher.decrypt(plain_text).unwrap();

        let mut hmac = HmacSha256::new_from_slice(&l).unwrap();
        // The HMAC is _just_ over the data fields, not their type. A little bit of a weird choice,
        // imho, but it does seems okay.
        let mut field_iteration = &plain_text[..];
        while let Some(field) = Self::next_buffered_field(field_iteration) {
            hmac.update(field.field_data);
            field_iteration = field.block_tail;
        }
        hmac.verify(&inner_mac)?;

        Ok(PwsafeReader {
            _inner: inner,
            buffer: Cursor::new(buffer),
            iter,
        })
    }

    pub fn restart(&mut self) {
        self.buffer.set_position(0);
    }

    /// Reads the database version field.
    pub fn read_version(&mut self) -> Result<u16> {
        let (field_type, data) = self.read_field()?.unwrap();
        let field = PwsafeHeaderField::new(field_type, data);
        if let Ok(PwsafeHeaderField::Version(version)) = field {
            return Ok(version);
        }
        Err(Error::InvalidHeader)
    }

    /// Reads a field.
    ///
    /// Returns field type and contents or `None` if EOF block is encountered.
    pub fn read_field(&mut self) -> Result<Option<(u8, Vec<u8>)>> {
        let tail = self.buffer.fill_buf()?;
        let Some(field) = Self::next_buffered_field(tail) else {
            return Ok(None);
        };

        let data = field.field_data.to_vec();
        let field_type = field.field_type;
        let consume = field.len;

        self.buffer.consume(consume);
        Ok(Some((field_type, data)))
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
