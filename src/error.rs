//! Error types and handling for the seal-crypto-wrapper library.
//!
//! seal-crypto-wrapper 库的错误类型和处理。
//!
//! ## Overview | 概述
//!
//! This module defines a comprehensive error hierarchy that covers all possible
//! failure modes in cryptographic operations. The error types are designed to
//! provide clear, actionable information while maintaining security by not
//! leaking sensitive details.
//!
//! 此模块定义了一个全面的错误层次结构，涵盖密码操作中所有可能的失败模式。
//! 错误类型旨在提供清晰、可操作的信息，同时通过不泄露敏感细节来维护安全性。
//!
//! ## Error Categories | 错误分类
//!
//! - **Cryptographic Errors**: Algorithm-specific failures from the underlying crypto library
//! - **OS Errors**: System-level failures (e.g., random number generation)
//! - **Format Errors**: Data serialization, key format, and ciphertext structure issues
//!
//! - **密码学错误**: 来自底层密码库的算法特定失败
//! - **操作系统错误**: 系统级失败（例如随机数生成）
//! - **格式错误**: 数据序列化、密钥格式和密文结构问题
//!
//! ## Error Handling Best Practices | 错误处理最佳实践
//!
//! - Always handle cryptographic errors gracefully
//! - Never ignore authentication failures
//! - Log errors appropriately without exposing sensitive data
//! - Use proper error propagation with the `?` operator
//!
//! - 始终优雅地处理密码学错误
//! - 永远不要忽略认证失败
//! - 适当记录错误而不暴露敏感数据
//! - 使用 `?` 操作符进行适当的错误传播

use rand::rand_core::OsError;
use thiserror::Error;

/// Main error type for the seal-crypto-wrapper library.
///
/// seal-crypto-wrapper 库的主要错误类型。
///
/// This enum encompasses all possible errors that can occur during cryptographic
/// operations. Each variant provides specific context about the failure mode.
///
/// 此枚举包含密码操作期间可能发生的所有错误。
/// 每个变体都提供有关失败模式的特定上下文。
#[derive(Error, Debug)]
pub enum Error {
    /// Errors from the underlying cryptographic library.
    ///
    /// 来自底层密码库的错误。
    ///
    /// These include algorithm-specific failures such as:
    /// - Key generation failures
    /// - Encryption/decryption errors
    /// - Signature verification failures
    /// - Invalid algorithm parameters
    ///
    /// 这些包括算法特定的失败，例如：
    /// - 密钥生成失败
    /// - 加密/解密错误
    /// - 签名验证失败
    /// - 无效的算法参数
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(#[from] seal_crypto::errors::Error),

    /// Operating system related errors.
    ///
    /// 操作系统相关错误。
    ///
    /// Typically occurs during:
    /// - Random number generation
    /// - System resource allocation
    /// - Hardware security module access
    ///
    /// 通常发生在：
    /// - 随机数生成
    /// - 系统资源分配
    /// - 硬件安全模块访问
    #[error("Operating system error: {0}")]
    OsError(#[from] OsError),

    /// Data format and serialization errors.
    ///
    /// 数据格式和序列化错误。
    ///
    /// Covers issues with:
    /// - Key serialization/deserialization
    /// - Ciphertext format validation
    /// - Algorithm parameter encoding
    ///
    /// 涵盖以下问题：
    /// - 密钥序列化/反序列化
    /// - 密文格式验证
    /// - 算法参数编码
    #[error("Data format error: {0}")]
    FormatError(#[from] FormatError),
}

/// Convenient Result type alias for this library.
///
/// 此库的便捷 Result 类型别名。
///
/// This type alias reduces boilerplate when working with functions that
/// return results from this library. Use this instead of `std::result::Result<T, Error>`.
///
/// 此类型别名在使用返回此库结果的函数时减少样板代码。
/// 使用此类型而不是 `std::result::Result<T, Error>`。
///
/// # Examples | 示例
///
/// ```rust
/// use seal_crypto_wrapper::error::Result;
///
/// fn encrypt_data(data: &[u8]) -> Result<Vec<u8>> {
///     // ... encryption logic
///     Ok(vec![])
/// }
/// ```
pub type Result<T> = std::result::Result<T, Error>;

/// Errors related to data formatting, serialization, and structure validation.
///
/// 与数据格式、序列化和结构验证相关的错误。
///
/// ## Overview | 概述
///
/// These errors occur when data doesn't conform to expected formats or when
/// serialization/deserialization operations fail. They typically indicate
/// either corrupted data or version incompatibilities.
///
/// 当数据不符合预期格式或序列化/反序列化操作失败时会发生这些错误。
/// 它们通常表示数据损坏或版本不兼容。
///
/// ## Common Causes | 常见原因
///
/// - Corrupted or truncated data
/// - Version mismatches between serialization formats
/// - Invalid key material or algorithm parameters
/// - Malformed ciphertext or signature data
///
/// - 损坏或截断的数据
/// - 序列化格式之间的版本不匹配
/// - 无效的密钥材料或算法参数
/// - 格式错误的密文或签名数据
#[derive(Debug, Error)]
pub enum FormatError {
    /// Binary serialization or deserialization failure.
    ///
    /// 二进制序列化或反序列化失败。
    ///
    /// This error occurs when `bincode` cannot serialize or deserialize data,
    /// typically due to:
    /// - Incompatible data structure versions
    /// - Corrupted serialized data
    /// - Insufficient buffer space
    ///
    /// 当 `bincode` 无法序列化或反序列化数据时发生此错误，通常由于：
    /// - 不兼容的数据结构版本
    /// - 损坏的序列化数据
    /// - 缓冲区空间不足
    ///
    /// # Recovery | 恢复
    ///
    /// - Verify data integrity
    /// - Check version compatibility
    /// - Ensure sufficient buffer space
    ///
    /// - 验证数据完整性
    /// - 检查版本兼容性
    /// - 确保足够的缓冲区空间
    #[error("Serialization/deserialization failed: {0}")]
    Serialization(#[from] BincodeError),

    /// Invalid or corrupted ciphertext format.
    ///
    /// 无效或损坏的密文格式。
    ///
    /// This error indicates that the ciphertext data is malformed, incomplete,
    /// or has been corrupted. Common causes include:
    /// - Data truncation during transmission or storage
    /// - Bit flips due to hardware errors
    /// - Incorrect data handling or parsing
    ///
    /// 此错误表示密文数据格式错误、不完整或已损坏。常见原因包括：
    /// - 传输或存储期间的数据截断
    /// - 硬件错误导致的位翻转
    /// - 不正确的数据处理或解析
    ///
    /// # Security Implications | 安全影响
    ///
    /// This error should be treated as a potential security issue.
    /// Never attempt to process malformed ciphertext.
    ///
    /// 此错误应被视为潜在的安全问题。
    /// 永远不要尝试处理格式错误的密文。
    #[error("Invalid or corrupted ciphertext format")]
    InvalidCiphertext,

    /// Unsupported or invalid key type.
    ///
    /// 不支持或无效的密钥类型。
    ///
    /// This error occurs when:
    /// - A key is used with an incompatible algorithm
    /// - The key type is not supported by the current configuration
    /// - Key metadata is corrupted or missing
    ///
    /// 在以下情况下发生此错误：
    /// - 密钥与不兼容的算法一起使用
    /// - 当前配置不支持密钥类型
    /// - 密钥元数据损坏或丢失
    #[error("Invalid or unsupported key type")]
    InvalidKeyType,

    /// Invalid key material or structure.
    ///
    /// 无效的密钥材料或结构。
    ///
    /// This error indicates that the key data itself is invalid:
    /// - Incorrect key length for the algorithm
    /// - Invalid key format or encoding
    /// - Corrupted key material
    /// - Missing required key components
    ///
    /// 此错误表示密钥数据本身无效：
    /// - 算法的密钥长度不正确
    /// - 无效的密钥格式或编码
    /// - 损坏的密钥材料
    /// - 缺少必需的密钥组件
    ///
    /// # Security Note | 安全注意
    ///
    /// Invalid keys should never be used for cryptographic operations.
    /// Always validate key material before use.
    ///
    /// 无效密钥永远不应用于密码操作。
    /// 使用前始终验证密钥材料。
    #[error("Invalid key material or structure")]
    InvalidKey,
}

/// Wrapper for `bincode` serialization and deserialization errors.
///
/// `bincode` 序列化和反序列化错误的包装器。
///
/// ## Purpose | 目的
///
/// This wrapper provides a consistent error handling interface for `bincode`
/// operations within the library. It abstracts the underlying `bincode` error
/// types while preserving error information and source chains.
///
/// 此包装器为库内的 `bincode` 操作提供一致的错误处理接口。
/// 它抽象了底层的 `bincode` 错误类型，同时保留错误信息和源链。
///
/// ## Usage Context | 使用上下文
///
/// These errors typically occur during:
/// - Key serialization for storage or transmission
/// - Key deserialization from stored or received data
/// - Algorithm parameter encoding/decoding
/// - Ciphertext metadata serialization
///
/// 这些错误通常发生在：
/// - 用于存储或传输的密钥序列化
/// - 从存储或接收的数据进行密钥反序列化
/// - 算法参数编码/解码
/// - 密文元数据序列化
#[derive(Error, Debug)]
pub enum BincodeError {
    /// Serialization (encoding) operation failed.
    ///
    /// 序列化（编码）操作失败。
    ///
    /// This occurs when converting Rust data structures to binary format fails.
    /// Common causes include:
    /// - Insufficient output buffer space
    /// - Unsupported data types
    /// - Memory allocation failures
    ///
    /// 当将 Rust 数据结构转换为二进制格式失败时发生。
    /// 常见原因包括：
    /// - 输出缓冲区空间不足
    /// - 不支持的数据类型
    /// - 内存分配失败
    #[error("Binary encoding failed: {0}")]
    Enc(#[source] Box<bincode::error::EncodeError>),

    /// Deserialization (decoding) operation failed.
    ///
    /// 反序列化（解码）操作失败。
    ///
    /// This occurs when converting binary data back to Rust structures fails.
    /// Common causes include:
    /// - Corrupted or truncated input data
    /// - Version incompatibilities
    /// - Invalid data format
    /// - Insufficient input data
    ///
    /// 当将二进制数据转换回 Rust 结构失败时发生。
    /// 常见原因包括：
    /// - 损坏或截断的输入数据
    /// - 版本不兼容
    /// - 无效的数据格式
    /// - 输入数据不足
    #[error("Binary decoding failed: {0}")]
    Dec(#[source] Box<bincode::error::DecodeError>),
}

impl From<bincode::error::EncodeError> for BincodeError {
    /// Converts a `bincode` encoding error into our wrapper type.
    ///
    /// 将 `bincode` 编码错误转换为我们的包装器类型。
    fn from(err: bincode::error::EncodeError) -> Self {
        BincodeError::Enc(Box::from(err))
    }
}

impl From<bincode::error::DecodeError> for BincodeError {
    /// Converts a `bincode` decoding error into our wrapper type.
    ///
    /// 将 `bincode` 解码错误转换为我们的包装器类型。
    fn from(err: bincode::error::DecodeError) -> Self {
        BincodeError::Dec(Box::from(err))
    }
}
