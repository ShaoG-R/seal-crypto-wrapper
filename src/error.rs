use rand::rand_core::OsError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Crypto error: {0}")]
    CryptoError(#[from] seal_crypto::errors::Error),

    #[error("OS error: {0}")]
    OsError(#[from] OsError),

    #[error("Format error: {0}")]
    FormatError(#[from] FormatError),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Errors related to data formatting and serialization.
///
/// 与数据格式和序列化相关的错误。
#[derive(Debug, Error)]
pub enum FormatError {
    /// A failure during `bincode` serialization or deserialization.
    ///
    /// `bincode` 序列化或反序列化期间的失败。
    #[error("序列化/反序列化失败: {0}")]
    Serialization(#[from] BincodeError),

    /// The ciphertext stream is incomplete or its format is incorrect.
    /// This often indicates data corruption or truncation.
    ///
    /// 密文流不完整或其格式不正确。
    /// 这通常表示数据损坏或被截断。
    #[error("密文格式不正确或流不完整")]
    InvalidCiphertext,

    /// The key type is invalid.
    ///
    /// 密钥类型无效。
    #[error("密钥类型无效")]
    InvalidKeyType,

    /// The key is invalid.
    ///
    /// 密钥无效。
    #[error("密钥无效")]
    InvalidKey,
}

/// An error related to `bincode` serialization or deserialization.
///
/// This is a wrapper around `bincode`'s own error types to provide a more
/// consistent error handling experience within this crate.
///
/// 与 `bincode` 序列化或反序列化相关的错误。
///
/// 这是对 `bincode` 自身错误类型的包装，以便在此 crate 中提供更一致的错误处理体验。
#[derive(Error, Debug)]
pub enum BincodeError {
    /// An error occurred during serialization (encoding).
    ///
    /// 在序列化（编码）过程中发生错误。
    #[error("Encode error: {0}")]
    Enc(#[source] Box<bincode::error::EncodeError>),
    /// An error occurred during deserialization (decoding).
    ///
    /// 在反序列化（解码）过程中发生错误。
    #[error("Decode error: {0}")]
    Dec(#[source] Box<bincode::error::DecodeError>),
}

impl From<bincode::error::EncodeError> for BincodeError {
    fn from(err: bincode::error::EncodeError) -> Self {
        BincodeError::Enc(Box::from(err))
    }
}

impl From<bincode::error::DecodeError> for BincodeError {
    fn from(err: bincode::error::DecodeError) -> Self {
        BincodeError::Dec(Box::from(err))
    }
}
