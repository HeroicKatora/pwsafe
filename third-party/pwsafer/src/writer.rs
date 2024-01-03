use block_padding::ZeroPadding;
use byteorder::{LittleEndian, WriteBytesExt};
use hmac::{Hmac, Mac, NewMac};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::cmp::min;
use std::io::{self, Cursor, Write};
use std::result::Result;
use twofish::cipher::crypto_common::generic_array::GenericArray;
use twofish::cipher::{BlockEncrypt, BlockEncryptMut, crypto_common::{KeyInit, KeyIvInit}};
use twofish::Twofish;

use crate::key::PwsafeKey;

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
/// db.write_field(0x00, &version).unwrap(); // Version field
/// db.write_field(0xff, &empty).unwrap(); // End of header
/// db.finish().unwrap(); // EOF and HMAC
/// ```
pub struct PwsafeWriter<W> {
    inner: W,
    buffer: Vec<u8>,
    k: [u8; 32],
    iv: [u8; 16],
    hmac: HmacSha256,
}

impl<W: Write> PwsafeWriter<W> {
    /// Creates a new `PwsafeWriter` with the given password.
    pub fn new(mut inner: W, iter: u32, key: &PwsafeKey) -> Result<Self, io::Error> {
        inner.write_all(b"PWS3")?;

        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        inner.write_all(&salt)?;
        inner.write_u32::<LittleEndian>(iter)?;

        let key = key.hash(&salt, iter);

        let mut hasher = Sha256::default();
        hasher.update(&key);
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

        let sha256_hmac = HmacSha256::new_from_slice(&l).unwrap();

        let twofish_cipher = Twofish::new(&key);
        for ch in k_.chunks_exact_mut(16) {
            twofish_cipher.encrypt_block(GenericArray::from_mut_slice(ch));
        }

        for ch in l_.chunks_exact_mut(16) {
            twofish_cipher.encrypt_block(GenericArray::from_mut_slice(ch));
        }

        inner.write_all(&k_)?;
        inner.write_all(&l_)?;
        inner.write_all(&iv_)?;

        let buffer = Vec::new();

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
    pub fn write_field(&mut self, field_type: u8, data: &[u8]) -> Result<(), io::Error> {
        let mut i: usize = 0;
        let mut block = [0u8; 16];
        let mut cur = Cursor::new(Vec::new());
        cur.write_u32::<LittleEndian>(data.len() as u32)?;
        cur.write_u8(field_type)?;

        self.hmac.update(&data);
        loop {
            let l = min(16 - cur.get_ref().len(), data.len() - i);
            cur.write_all(&data[i..i + l])?;

            if l == 0 {
                i += 16
            } else {
                i += l;
            }

            let v = cur.into_inner();
            let vlen = v.len();
            block[0..vlen].copy_from_slice(&v);
            OsRng.fill_bytes(&mut block[vlen..16]); // Pad with random bytes

            self.buffer.append(&mut block.to_vec());

            cur = Cursor::new(Vec::new());
            if i >= data.len() {
                break;
            }
        }
        Ok(())
    }

    /// Encrypts/Writes all fields, EOF block and HMAC.
    pub fn finish(&mut self) -> Result<(), io::Error> {
        let mut fields = self.buffer.clone();
        let pos = self.buffer.len();
        let cbc_cipher = TwofishCbc::new_from_slices(&self.k, &self.iv).unwrap();
        cbc_cipher.encrypt_padded_mut::<ZeroPadding>(&mut fields, pos).unwrap();
        self.inner.write_all(&fields)?;
        self.inner.write_all(b"PWS3-EOFPWS3-EOF")?;
        self.inner.write_all(&self.hmac.clone().finalize().into_bytes())?;
        Ok(())
    }
}
