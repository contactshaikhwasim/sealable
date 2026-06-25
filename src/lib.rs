pub mod prelude {
    pub use super::{
        codec::Base64Url,
        crypto::{Aes256Gcm, Argon2id},
        SealedBox,
    };

    pub type DefaultSealedBox = SealedBox<Aes256Gcm, Argon2id, Base64Url>;
}

mod error;
pub use error::Error;

pub mod traits;
pub mod crypto;
pub mod codec;

use traits::{Cipher, Codec, KeyDerivation};
use zeroize::Zeroizing;

pub struct SealedBox<C, K, E> {
    _phantom: std::marker::PhantomData<(C, K, E)>,
}

impl<C: Cipher, K: KeyDerivation, E: Codec> SealedBox<C, K, E> {
    pub fn encrypt(passphrase: &str, plaintext: &[u8]) -> Result<String, Error> {
        let salt = K::generate_salt();
        let key = K::derive(passphrase, &salt)?;
        let nonce = C::generate_nonce();
        let ciphertext = C::encrypt(&key, &nonce, plaintext)?;

        let version: u8 = 1;
        let mut payload = Vec::with_capacity(1 + salt.len() + nonce.len() + ciphertext.len());
        payload.push(version);
        payload.extend_from_slice(&salt);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);

        E::encode(&payload)
    }

    pub fn decrypt(passphrase: &str, sealed: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
        let payload = E::decode(sealed)?;

        if payload.is_empty() {
            return Err(Error::InvalidFormat("empty payload".into()));
        }
        let version = payload[0];
        if version != 1 {
            return Err(Error::UnsupportedVersion(version));
        }

        let salt_len = K::SALT_LEN;
        let nonce_len = C::NONCE_LEN;
        let total_needed = 1 + salt_len + nonce_len;
        if payload.len() < total_needed {
            return Err(Error::InvalidFormat("payload too short".into()));
        }

        let salt = &payload[1..1 + salt_len];
        let nonce = &payload[1 + salt_len..total_needed];
        let ciphertext = &payload[total_needed..];

        let key = K::derive(passphrase, salt)?;
        let plaintext = C::decrypt(&key, nonce, ciphertext)?;
        Ok(Zeroizing::new(plaintext))
    }
}