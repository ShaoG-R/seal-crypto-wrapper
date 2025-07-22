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

// Hash algorithms | 哈希算法
pub mod hash;
