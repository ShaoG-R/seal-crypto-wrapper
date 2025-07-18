
//! Asymmetric cryptography algorithms and key management.
//!
//! 非对称密码算法和密钥管理。
//!
//! ## Overview | 概述
//!
//! This module provides asymmetric (public-key) cryptographic algorithms that enable
//! secure communication without prior key exchange. It includes both traditional
//! algorithms and post-quantum cryptography for future security.
//!
//! 此模块提供非对称（公钥）密码算法，无需事先密钥交换即可实现安全通信。
//! 它包括传统算法和后量子密码学以确保未来安全。
//!
//! ## Algorithm Categories | 算法分类
//!
//! ### Key Encapsulation Mechanisms (KEM) | 密钥封装机制
//! - **RSA**: Traditional public-key cryptosystem
//! - **Kyber**: Post-quantum lattice-based KEM (NIST standard)
//!
//! ### Digital Signatures | 数字签名
//! - **Ed25519**: Edwards curve signatures (high performance)
//! - **ECDSA P-256**: NIST standard elliptic curve signatures
//! - **Dilithium**: Post-quantum lattice-based signatures (NIST standard)
//!
//! ### Key Agreement | 密钥协商
//! - **ECDH P-256**: Elliptic Curve Diffie-Hellman
//!
//! ## Security Considerations | 安全考虑
//!
//! ### Traditional vs Post-Quantum | 传统 vs 后量子
//!
//! - **Traditional algorithms** (RSA, ECDSA, ECDH): Secure against classical computers
//! - **Post-quantum algorithms** (Kyber, Dilithium): Secure against quantum computers
//!
//! - **传统算法**（RSA、ECDSA、ECDH）：对经典计算机安全
//! - **后量子算法**（Kyber、Dilithium）：对量子计算机安全
//!
//! ### Migration Strategy | 迁移策略
//!
//! For long-term security, consider hybrid approaches or gradual migration to
//! post-quantum algorithms as they become more widely adopted.
//!
//! 为了长期安全，考虑混合方法或随着后量子算法更广泛采用而逐步迁移。

// Digital signature algorithms | 数字签名算法
#[cfg(feature = "asymmetric-signature")]
pub mod signature;

// Key encapsulation mechanisms | 密钥封装机制
#[cfg(feature = "asymmetric-kem")]
pub mod kem;

// Key agreement protocols | 密钥协商协议
#[cfg(feature = "asymmetric-key-agreement")]
pub mod key_agreement;

#[cfg(feature = "asymmetric-kem")]
use self::kem::KemAlgorithm;
#[cfg(feature = "asymmetric-signature")]
use self::signature::SignatureAlgorithm;

/// Asymmetric cryptography algorithm enumeration.
///
/// 非对称密码算法枚举。
///
/// ## Purpose | 目的
///
/// This enum serves as a unified interface for all asymmetric cryptographic
/// operations, allowing runtime algorithm selection while maintaining type safety.
///
/// 此枚举作为所有非对称密码操作的统一接口，
/// 允许运行时算法选择同时保持类型安全。
///
/// ## Usage Pattern | 使用模式
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::asymmetric::AsymmetricAlgorithm;
///
/// // Key encapsulation
/// let kem = AsymmetricAlgorithm::build().kem().kyber512();
///
/// // Digital signatures
/// let sig = AsymmetricAlgorithm::build().signature().ed25519();
///
/// // Key agreement
/// let ka = AsymmetricAlgorithm::build().key_agreement().ecdh_p256();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AsymmetricAlgorithm {
    /// Key Encapsulation Mechanism algorithms.
    ///
    /// 密钥封装机制算法。
    ///
    /// Used for securely establishing shared secrets between parties.
    /// Particularly important for post-quantum security.
    ///
    /// 用于在各方之间安全建立共享密钥。
    /// 对后量子安全特别重要。
    #[cfg(feature = "asymmetric-kem")]
    Kem(KemAlgorithm),

    /// Digital signature algorithms.
    ///
    /// 数字签名算法。
    ///
    /// Used for authentication, non-repudiation, and data integrity.
    /// Essential for secure communications and document signing.
    ///
    /// 用于认证、不可否认性和数据完整性。
    /// 对安全通信和文档签名至关重要。
    #[cfg(feature = "asymmetric-signature")]
    Signature(SignatureAlgorithm),
}

impl AsymmetricAlgorithm {
    /// Creates a new asymmetric algorithm builder.
    ///
    /// 创建新的非对称算法构建器。
    ///
    /// ## Returns | 返回值
    ///
    /// A builder that provides access to different asymmetric algorithm categories.
    /// Use the builder methods to select the specific algorithm type needed.
    ///
    /// 提供访问不同非对称算法类别的构建器。
    /// 使用构建器方法选择所需的特定算法类型。
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::asymmetric::AsymmetricAlgorithm;
    ///
    /// // Build different algorithm types
    /// let kem = AsymmetricAlgorithm::build().kem().kyber512();
    /// let sig = AsymmetricAlgorithm::build().signature().ed25519();
    /// ```
    pub fn build() -> AsymmetricAlgorithmBuilder {
        AsymmetricAlgorithmBuilder
    }
}

/// Builder for constructing asymmetric algorithm instances.
///
/// 用于构建非对称算法实例的构建器。
///
/// ## Design Pattern | 设计模式
///
/// This builder follows a fluent interface pattern, allowing method chaining
/// to construct the desired algorithm configuration. Each method returns a
/// specialized builder for that algorithm category.
///
/// 此构建器遵循流畅接口模式，允许方法链接来构建所需的算法配置。
/// 每个方法都返回该算法类别的专用构建器。
///
/// ## Algorithm Selection Guide | 算法选择指南
///
/// - **KEM**: For secure key establishment and hybrid encryption
/// - **Signatures**: For authentication and non-repudiation
/// - **Key Agreement**: For establishing shared secrets
///
/// - **KEM**: 用于安全密钥建立和混合加密
/// - **签名**: 用于认证和不可否认性
/// - **密钥协商**: 用于建立共享密钥
pub struct AsymmetricAlgorithmBuilder;

impl AsymmetricAlgorithmBuilder {
    /// Creates a KEM (Key Encapsulation Mechanism) algorithm builder.
    ///
    /// 创建 KEM（密钥封装机制）算法构建器。
    ///
    /// ## Use Cases | 使用场景
    ///
    /// - Hybrid encryption schemes
    /// - Secure key establishment
    /// - Post-quantum secure communications
    ///
    /// - 混合加密方案
    /// - 安全密钥建立
    /// - 后量子安全通信
    ///
    /// ## Available Algorithms | 可用算法
    ///
    /// - **RSA**: Traditional, widely supported
    /// - **Kyber**: Post-quantum, NIST standardized
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::asymmetric::AsymmetricAlgorithm;
    ///
    /// let kyber = AsymmetricAlgorithm::build().kem().kyber768();
    /// let rsa = AsymmetricAlgorithm::build().kem().rsa2048().sha256();
    /// ```
    #[cfg(feature = "asymmetric-kem")]
    pub fn kem(self) -> kem::KemAlgorithmBuilder {
        KemAlgorithm::build()
    }

    /// Creates a digital signature algorithm builder.
    ///
    /// 创建数字签名算法构建器。
    ///
    /// ## Use Cases | 使用场景
    ///
    /// - Document signing and verification
    /// - Authentication protocols
    /// - Software integrity verification
    /// - Blockchain and cryptocurrency
    ///
    /// - 文档签名和验证
    /// - 认证协议
    /// - 软件完整性验证
    /// - 区块链和加密货币
    ///
    /// ## Available Algorithms | 可用算法
    ///
    /// - **Ed25519**: High performance, modern
    /// - **ECDSA P-256**: NIST standard, widely supported
    /// - **Dilithium**: Post-quantum, NIST standardized
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::asymmetric::AsymmetricAlgorithm;
    ///
    /// let ed25519 = AsymmetricAlgorithm::build().signature().ed25519();
    /// let dilithium = AsymmetricAlgorithm::build().signature().dilithium2();
    /// ```
    #[cfg(feature = "asymmetric-signature")]
    pub fn signature(self) -> signature::SignatureAlgorithmBuilder {
        SignatureAlgorithm::build()
    }

    /// Creates a key agreement algorithm builder.
    ///
    /// 创建密钥协商算法构建器。
    ///
    /// ## Use Cases | 使用场景
    ///
    /// - Establishing shared secrets
    /// - Secure channel establishment
    /// - Forward secrecy protocols
    ///
    /// - 建立共享密钥
    /// - 安全通道建立
    /// - 前向保密协议
    ///
    /// ## Available Algorithms | 可用算法
    ///
    /// - **ECDH P-256**: Elliptic Curve Diffie-Hellman
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::asymmetric::AsymmetricAlgorithm;
    ///
    /// let ecdh = AsymmetricAlgorithm::build().key_agreement().ecdh_p256();
    /// ```
    #[cfg(feature = "asymmetric-key-agreement")]
    pub fn key_agreement(self) -> key_agreement::KeyAgreementAlgorithmBuilder {
        key_agreement::KeyAgreementAlgorithm::build()
    }
}