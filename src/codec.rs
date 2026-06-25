use crate::{traits::Codec, Error};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

pub struct Base64Url;

impl Codec for Base64Url {
    fn encode(data: &[u8]) -> Result<String, Error> {
        Ok(URL_SAFE_NO_PAD.encode(data))
    }

    fn decode(encoded: &str) -> Result<Vec<u8>, Error> {
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| Error::Encoding(format!("base64 decode error: {}", e)))
    }
}