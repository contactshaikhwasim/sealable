use crate::{traits::*, Error};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm as AesGcmInner, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use rand::RngCore;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Argon2id key derivation
// ---------------------------------------------------------------------------
pub struct Argon2id;

impl KeyDerivation for Argon2id {
    const SALT_LEN: usize = 16; // 128-bit salt
    const KEY_LEN: usize = 32;  // 256-bit key for AES-256

    fn generate_salt() -> Vec<u8> {
        let mut salt = vec![0u8; Self::SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    fn derive(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        // Convert raw bytes into a SaltString (uses base64 internally)
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| Error::Crypto(format!("invalid salt: {}", e)))?;

        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(passphrase.as_bytes(), &salt_string)
            .map_err(|e| Error::Crypto(format!("argon2 error: {}", e)))?;

        // The hash output contains the derived key material; we truncate to KEY_LEN.
        // (In production, use a proper KDF like HKDF-Expand.)
        let raw = hash.hash.unwrap().as_bytes().to_vec();
        let key = Zeroizing::new(raw[..Self::KEY_LEN].to_vec());
        Ok(key)
    }
}

// ---------------------------------------------------------------------------
// AES-256-GCM cipher
// ---------------------------------------------------------------------------
pub struct Aes256Gcm;

impl Cipher for Aes256Gcm {
    const NONCE_LEN: usize = 12; // 96-bit nonce

    fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; Self::NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = AesGcmInner::new_from_slice(key)
            .map_err(|_| Error::Crypto("invalid key length".into()))?;
        let nonce = Nonce::from_slice(nonce);
        cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| Error::Crypto(format!("encryption failed: {}", e)))
    }

    fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = AesGcmInner::new_from_slice(key)
            .map_err(|_| Error::Crypto("invalid key length".into()))?;
        let nonce = Nonce::from_slice(nonce);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| Error::Crypto(format!("decryption failed: {}", e)))
    }
}