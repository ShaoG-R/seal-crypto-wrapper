//! Prelude module for convenient imports.
//!
//! 用于便捷导入的预导入模块。
//!
//! ## Overview | 概述
//!
//! This module re-exports the most commonly used types and traits from the library,
//! allowing users to import everything they need with a single `use` statement.
//!
//! 此模块重新导出库中最常用的类型和 trait，允许用户通过单个 `use` 语句导入所需的一切。
//!
//! ## Usage | 使用方法
//!
//! ```rust
//! use seal_crypto_wrapper::prelude::*;
//! ```
//!
//! This will import all the commonly used types based on the enabled features.
//!
//! 这将根据启用的功能导入所有常用类型。
//!
//! ## Imported Types by Feature | 按功能导入的类型
//!
//! ### Asymmetric Cryptography | 非对称密码学
//!
//! Available when any asymmetric feature is enabled.
//!
//! 在启用任何非对称功能时可用。

// Core asymmetric algorithm types | 核心非对称算法类型
#[cfg(any(
    feature = "asymmetric-kem",
    feature = "asymmetric-signature",
    feature = "asymmetric-key-agreement"
))]
mod asymmetric {
    /// Builder for asymmetric algorithms | 非对称算法构建器
    pub use crate::algorithms::asymmetric::AsymmetricAlgorithm;

    /// Untyped asymmetric private key | 非类型化非对称私钥
    pub use crate::keys::asymmetric::{AsymmetricPrivateKey, AsymmetricPublicKey};

    /// Core traits for typed asymmetric keys | 类型化非对称密钥的核心 trait
    pub use crate::keys::asymmetric::{
        TypedAsymmetricKeyTrait, TypedAsymmetricPrivateKeyTrait, TypedAsymmetricPublicKeyTrait,
    };

    // Key Encapsulation Mechanism (KEM) types | 密钥封装机制 (KEM) 类型
    #[cfg(feature = "asymmetric-kem")]
    pub(super) mod kem {
        /// Encapsulated key result from KEM operations | KEM 操作产生的封装密钥结果
        pub use crate::keys::asymmetric::kem::EncapsulatedKey;
        /// Typed KEM key pair | 类型化 KEM 密钥对
        pub use crate::keys::asymmetric::kem::TypedKemKeyPair;
        /// Typed KEM private key | 类型化 KEM 私钥
        pub use crate::keys::asymmetric::kem::TypedKemPrivateKey;
        /// Typed KEM public key | 类型化 KEM 公钥
        pub use crate::keys::asymmetric::kem::TypedKemPublicKey;
    }

    // Digital signature types | 数字签名类型
    #[cfg(feature = "asymmetric-signature")]
    pub(super) mod signature {
        /// Typed signature key pair | 类型化签名密钥对
        pub use crate::keys::asymmetric::signature::TypedSignatureKeyPair;
        /// Typed signature private key | 类型化签名私钥
        pub use crate::keys::asymmetric::signature::TypedSignaturePrivateKey;
        /// Typed signature public key | 类型化签名公钥
        pub use crate::keys::asymmetric::signature::TypedSignaturePublicKey;
        /// Signature type | 签名类型
        pub use seal_crypto::prelude::Signature;
    }

    // Key agreement types | 密钥协商类型
    #[cfg(feature = "asymmetric-key-agreement")]
    pub(super) mod key_agreement {
        /// Typed key agreement key pair | 类型化密钥协商密钥对
        pub use crate::keys::asymmetric::key_agreement::TypedKeyAgreementKeyPair;
        /// Typed key agreement private key | 类型化密钥协商私钥
        pub use crate::keys::asymmetric::key_agreement::TypedKeyAgreementPrivateKey;
        /// Typed key agreement public key | 类型化密钥协商公钥
        pub use crate::keys::asymmetric::key_agreement::TypedKeyAgreementPublicKey;
    }
}

#[cfg(any(
    feature = "asymmetric-kem",
    feature = "asymmetric-signature",
    feature = "asymmetric-key-agreement"
))]
pub use asymmetric::*;

#[cfg(feature = "asymmetric-kem")]
pub use kem::*;

#[cfg(feature = "asymmetric-signature")]
pub use signature::*;

#[cfg(feature = "asymmetric-key-agreement")]
pub use key_agreement::*;

// Key Derivation Function (KDF) types | 密钥派生函数 (KDF) 类型
#[cfg(feature = "kdf")]
mod kdf {
    /// KDF algorithm builder | KDF 算法构建器
    pub use crate::algorithms::kdf::KdfAlgorithm;
    /// Traits for key-based and password-based KDF | 基于密钥和基于密码的 KDF trait
    pub use crate::traits::{KdfKeyAlgorithmTrait, KdfPasswordAlgorithmTrait};
}

#[cfg(feature = "kdf")]
pub use kdf::*;

#[cfg(feature = "aead")]
// Aead cryptography types | 对称密码学类型
mod aead {
    /// Aead algorithm builder | 对称算法构建器
    pub use crate::algorithms::aead::AeadAlgorithm;
    /// Untyped aead key | 非类型化对称密钥
    pub use crate::keys::aead::AeadKey;
    /// Typed aead key with algorithm binding | 带算法绑定的类型化对称密钥
    pub use crate::keys::aead::TypedAeadKey;
}

#[cfg(feature = "aead")]
pub use aead::*;

// Extendable Output Function (XOF) types | 可扩展输出函数 (XOF) 类型
#[cfg(feature = "xof")]
mod xof {
    /// XOF algorithm builder | XOF 算法构建器
    pub use crate::algorithms::xof::XofAlgorithm;
    /// Trait for XOF algorithms | XOF 算法 trait
    pub use crate::traits::XofAlgorithmTrait;
}

#[cfg(feature = "xof")]
pub use xof::*;

// Security and memory management utilities | 安全和内存管理工具

/// Zero-on-drop wrapper for sensitive data.
///
/// 敏感数据的零化销毁包装器。
///
/// Automatically zeros memory when the value is dropped, preventing sensitive
/// data from remaining in memory after use.
///
/// 当值被丢弃时自动清零内存，防止敏感数据在使用后仍留在内存中。
pub use ::seal_crypto::zeroize::Zeroizing;

/// Secret box for protecting sensitive data in memory.
///
/// 用于保护内存中敏感数据的秘密盒子。
///
/// Provides additional protection for sensitive data like passwords and keys
/// by preventing accidental exposure through debug output or memory dumps.
///
/// 通过防止通过调试输出或内存转储意外暴露，为密码和密钥等敏感数据提供额外保护。
pub use ::seal_crypto::secrecy::SecretBox;
