use secrets::SecretBox;
use sha2::{Digest, Sha256};

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

    pub fn hash(&self, salt: &[u8], iter: u32) -> SecretBox<[u8; 32]> {
        let mut boxed: SecretBox<[u8; 32]> = SecretBox::zero();
        let mut hasher = self.prepared_password.clone();
        hasher.update(&salt);

        let mut workmemory = boxed.borrow_mut();

        {
            hasher.finalize_into((&mut *workmemory).into());
        }

        for _ in 0..iter {
            let mut hasher = Sha256::default();
            hasher.update(&*workmemory);
            hasher.finalize_into((&mut *workmemory).into());
        }

        drop(workmemory);
        boxed
    }
}
