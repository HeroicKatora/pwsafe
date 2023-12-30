use sha2::{Digest, Sha256};

use twofish::cipher::generic_array::typenum::U32;
use twofish::cipher::generic_array::GenericArray;

pub struct PwsafeKey {
    /// The digested password, not yet salted and iterated.
    prepared_password: Sha256,
}

impl PwsafeKey {
    pub fn new(password: &[u8]) -> Self {
        let mut prepared_password = Sha256::default();
        prepared_password.update(password);
        PwsafeKey { prepared_password }
    }

    pub fn hash(&self, salt: &[u8], iter: u32) -> GenericArray<u8, U32> {
        let mut hasher = self.prepared_password.clone();
        hasher.update(&salt);
        let mut key = hasher.finalize();
        for _ in 0..iter {
            let mut hasher = Sha256::default();
            hasher.update(&key);
            key = hasher.finalize();
        }
        key
    }
}

/// Returns ECB key generated from password using key stretching algorithm.
pub fn hash_password(salt: &[u8], iter: u32, password: &[u8]) -> GenericArray<u8, U32> {
    let key = PwsafeKey::new(password);
    key.hash(salt, iter)
}
