use crate::Error;
use zeroize::Zeroizing;

pub trait KeyDerivation {
    const SALT_LEN: usize;
    const KEY_LEN: usize;

    fn generate_salt() -> Vec<u8>;
    fn derive(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>;
}

pub trait Cipher {
    const NONCE_LEN: usize;

    fn generate_nonce() -> Vec<u8>;
    fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error>;
    fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait Codec {
    fn encode(data: &[u8]) -> Result<String, Error>;
    fn decode(encoded: &str) -> Result<Vec<u8>, Error>;
}
