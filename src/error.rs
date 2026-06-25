#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported version {0}")]
    UnsupportedVersion(u8),

    #[error("invalid payload format: {0}")]
    InvalidFormat(String),

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("encoding error: {0}")]
    Encoding(String),
}