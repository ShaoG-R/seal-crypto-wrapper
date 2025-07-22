//! Cryptographic algorithm definitions and builders.
//!
//! 密码算法定义和构建器。
//!
//! ## Overview | 概述
//!
//! This module contains all cryptographic algorithm definitions, builders, and enumerations
//! used throughout the library. It provides a unified interface for selecting and configuring
//! different cryptographic primitives.
//!
//! 此模块包含库中使用的所有密码算法定义、构建器和枚举。
//! 它为选择和配置不同的密码原语提供统一接口。
//!
//! ## Algorithm Categories | 算法分类
//!
//! ### Aead Cryptography | 对称密码学
//! - **AES-GCM**: Advanced Encryption Standard with Galois/Counter Mode
//! - **ChaCha20-Poly1305**: ChaCha20 stream cipher with Poly1305 authenticator
//! - **XChaCha20-Poly1305**: Extended nonce variant of ChaCha20-Poly1305
//!
//! ### Asymmetric Cryptography | 非对称密码学
//! - **RSA**: Traditional public-key cryptosystem
//! - **Elliptic Curve**: ECDSA signatures and ECDH key agreement
//! - **Post-Quantum**: Kyber (KEM) and Dilithium (signatures)
//!
//! ### Key Derivation | 密钥派生
//! - **HKDF**: HMAC-based Key Derivation Function
//! - **PBKDF2**: Password-Based Key Derivation Function 2
//! - **Argon2**: Memory-hard password hashing function
//!
//! ### Extendable Output Functions | 可扩展输出函数
//! - **SHAKE**: SHA-3 derived functions with variable output length
//!
//! ## Security Levels | 安全级别
//!
//! All algorithms are categorized by their security strength:
//! - **128-bit security**: Suitable for most applications
//! - **192-bit security**: High security requirements
//! - **256-bit security**: Maximum security for long-term protection
//!
//! 所有算法按其安全强度分类：
//! - **128 位安全性**: 适用于大多数应用
//! - **192 位安全性**: 高安全性要求
//! - **256 位安全性**: 长期保护的最大安全性

// Asymmetric cryptography algorithms | 非对称密码算法
#[cfg(any(
    feature = "asymmetric-kem",
    feature = "asymmetric-signature",
    feature = "asymmetric-key-agreement"
))]
pub mod asymmetric;

// Key derivation functions | 密钥派生函数
#[cfg(feature = "kdf")]
pub mod kdf;

// Aead encryption algorithms | 对称加密算法
#[cfg(feature = "aead")]
pub mod aead;

// Extendable output functions | 可扩展输出函数
#[cfg(feature = "xof")]
pub mod xof;

#[allow(unused)]
use bincode::{Decode, Encode};

/// Hash algorithm enumeration for cryptographic operations.
///
/// 用于密码操作的哈希算法枚举。
///
/// ## Overview | 概述
///
/// This enum represents the supported hash algorithms used in various cryptographic
/// constructions such as HMAC, digital signatures, and key derivation functions.
///
/// 此枚举表示在各种密码构造中使用的支持的哈希算法，
/// 如 HMAC、数字签名和密钥派生函数。
///
/// ## Security Properties | 安全属性
///
/// All included hash functions are cryptographically secure and provide:
/// - **Collision resistance**: Computationally infeasible to find two inputs with same hash
/// - **Preimage resistance**: Given a hash, infeasible to find the original input
/// - **Second preimage resistance**: Given an input, infeasible to find another with same hash
///
/// 所有包含的哈希函数都是密码学安全的，并提供：
/// - **抗碰撞性**: 计算上不可行找到具有相同哈希的两个输入
/// - **原像抗性**: 给定哈希值，不可行找到原始输入
/// - **第二原像抗性**: 给定输入，不可行找到另一个具有相同哈希的输入
///
/// ## Algorithm Details | 算法详情
///
/// | Algorithm | Output Size | Security Level | Performance | Use Cases |
/// |-----------|-------------|----------------|-------------|-----------|
/// | SHA-256   | 256 bits    | 128-bit        | High        | General purpose, Bitcoin |
/// | SHA-384   | 384 bits    | 192-bit        | Medium      | High security applications |
/// | SHA-512   | 512 bits    | 256-bit        | Medium      | Maximum security, long-term |
///
/// ## Usage Guidelines | 使用指南
///
/// - **SHA-256**: Recommended for most applications, widely supported
/// - **SHA-384**: Use when 192-bit security level is required
/// - **SHA-512**: Use for maximum security or when working with 64-bit architectures
///
/// - **SHA-256**: 推荐用于大多数应用，广泛支持
/// - **SHA-384**: 需要 192 位安全级别时使用
/// - **SHA-512**: 用于最大安全性或在 64 位架构上工作时使用
#[allow(unused)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, serde::Serialize, serde::Deserialize,
)]
pub enum HashAlgorithmEnum {
    /// SHA-256 hash algorithm (256-bit output, 128-bit security).
    ///
    /// SHA-256 哈希算法（256 位输出，128 位安全性）。
    ///
    /// Most widely used and supported hash function. Suitable for general-purpose
    /// cryptographic applications including digital signatures, HMAC, and key derivation.
    ///
    /// 最广泛使用和支持的哈希函数。适用于通用密码应用，
    /// 包括数字签名、HMAC 和密钥派生。
    Sha256,

    /// SHA-384 hash algorithm (384-bit output, 192-bit security).
    ///
    /// SHA-384 哈希算法（384 位输出，192 位安全性）。
    ///
    /// Provides higher security level than SHA-256. Recommended for applications
    /// requiring 192-bit security strength.
    ///
    /// 提供比 SHA-256 更高的安全级别。推荐用于需要 192 位安全强度的应用。
    Sha384,

    /// SHA-512 hash algorithm (512-bit output, 256-bit security).
    ///
    /// SHA-512 哈希算法（512 位输出，256 位安全性）。
    ///
    /// Provides maximum security level. Recommended for long-term security
    /// requirements and high-value applications.
    ///
    /// 提供最大安全级别。推荐用于长期安全要求和高价值应用。
    Sha512,
}
