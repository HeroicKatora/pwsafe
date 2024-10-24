use block_padding::ZeroPadding;
use byteorder::{LittleEndian, WriteBytesExt};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use std::result::Result;
use twofish::cipher::crypto_common::generic_array::GenericArray;
use twofish::cipher::{
    crypto_common::{KeyInit, KeyIvInit},
    BlockEncrypt, BlockEncryptMut,
};
use twofish::Twofish;

use crate::key::PwsafeKey;
use crate::secrets_vec::SecretBuffer;

type TwofishCbc = cbc::Encryptor<Twofish>;
type HmacSha256 = Hmac<Sha256>;

/// Password safe writer.
///
/// # Examples
///
/// An example shows how to create an empty database.
/// ```no_run
/// use pwsafer::{PwsafeKey, PwsafeWriter};
/// use std::fs::File;
/// use std::io::BufWriter;
///
/// let filename = "pwsafe.psafe3";
/// let key = PwsafeKey::new(b"password");
///
/// let file = BufWriter::new(File::create(filename).unwrap());
/// let mut db = PwsafeWriter::new(file, 2048, &key).unwrap();
/// let version = [0x0eu8, 0x03u8];
/// let empty = [0u8, 0];
/// db.write_field(0x00, &version); // Version field
/// db.write_field(0xff, &empty); // End of header
/// db.finish().unwrap(); // EOF and HMAC
/// ```
pub struct PwsafeWriter<W> {
    inner: W,
    buffer: SecretBuffer,
    k: [u8; 32],
    iv: [u8; 16],
    hmac: HmacSha256,
}

impl<W> PwsafeWriter<W> {
    /// Creates a new `PwsafeWriter` with the given password.
    pub fn new(mut inner: W, iter: u32, key: &PwsafeKey) -> Result<Self, io::Error>
    where
        W: Write,
    {
        inner.write_all(b"PWS3")?;

        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        inner.write_all(&salt)?;
        inner.write_u32::<LittleEndian>(iter)?;

        let key = key.hash(&salt, iter);
        let key = key.borrow();

        let mut hasher = Sha256::default();
        hasher.update(&*key);
        let hash = hasher.finalize();
        inner.write_all(&hash)?;

        let mut k = [0u8; 32];
        let mut l = [0u8; 32];
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut k);
        OsRng.fill_bytes(&mut l);
        OsRng.fill_bytes(&mut iv);

        let mut k_ = k.clone();
        let mut l_ = l.clone();
        let iv_ = iv.clone();

        let sha256_hmac: HmacSha256 = Mac::new_from_slice(&l).unwrap();

        let twofish_cipher = Twofish::new((&*key).into());
        for ch in k_.chunks_exact_mut(16) {
            twofish_cipher.encrypt_block(GenericArray::from_mut_slice(ch));
        }

        for ch in l_.chunks_exact_mut(16) {
            twofish_cipher.encrypt_block(GenericArray::from_mut_slice(ch));
        }

        inner.write_all(&k_)?;
        inner.write_all(&l_)?;
        inner.write_all(&iv_)?;

        let buffer = SecretBuffer::new();

        let w = PwsafeWriter {
            inner,
            buffer,
            k,
            iv,
            hmac: sha256_hmac,
        };
        Ok(w)
    }

    /// Prepares one field.
    pub fn write_field(&mut self, field_type: u8, data: &[u8]) {
        // The block which may be partially rng filled.
        let i;
        let mut block = [0u8; 16];
        block[..4].copy_from_slice(&(data.len() as u32).to_le_bytes());
        block[4] = field_type;

        self.hmac.update(&data);

        if data.len() > 11 {
            let (front, tail) = data.split_at(11);
            block[5..].copy_from_slice(front);
            self.buffer.extend_from_slice(&block);

            let remainder = tail.chunks_exact(16).remainder();
            let raw_len = tail.len() - remainder.len();
            debug_assert!(raw_len % 16 == 0);
            self.buffer.extend_from_slice(&data[..raw_len]);

            if remainder.len() == 0 {
                return;
            }

            i = remainder.len();
            block[..remainder.len()].copy_from_slice(remainder);
        } else {
            let len = data.len();
            i = 5 + len;
            block[5..][..len].copy_from_slice(data);
        };

        OsRng.fill_bytes(&mut block[i..16]); // Pad with random bytes
        self.buffer.extend_from_slice(&block);
    }

    /// Encrypts/Writes all fields, EOF block and HMAC.
    pub fn finish(&mut self) -> Result<(), io::Error>
    where
        W: Write,
    {
        let mut fields = self.buffer.to_owned();
        let mut fields = fields.borrow_mut();
        let pos = fields.len();

        let cbc_cipher = TwofishCbc::new_from_slices(&self.k, &self.iv).unwrap();
        cbc_cipher
            .encrypt_padded_mut::<ZeroPadding>(&mut fields, pos)
            .unwrap();

        self.inner.write_all(&fields)?;
        self.inner.write_all(b"PWS3-EOFPWS3-EOF")?;
        self.inner
            .write_all(&self.hmac.clone().finalize().into_bytes())?;

        Ok(())
    }

    pub fn take(self) -> (PwsafeWriter<()>, W) {
        let writer = PwsafeWriter {
            inner: (),
            buffer: self.buffer,
            k: self.k,
            iv: self.iv,
            hmac: self.hmac,
        };

        (writer, self.inner)
    }
}
