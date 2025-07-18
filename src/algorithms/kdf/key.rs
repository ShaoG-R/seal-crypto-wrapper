
//! Key-based Key Derivation Functions (KDF) for high-entropy inputs.
//!
//! 用于高熵输入的基于密钥的密钥派生函数 (KDF)。
//!
//! ## Overview | 概述
//!
//! Key-based KDFs are designed to work with high-entropy input key material,
//! such as cryptographic keys, shared secrets from key agreement protocols,
//! or other sources with sufficient randomness. They efficiently expand or
//! derive multiple keys from a single master key.
//!
//! 基于密钥的 KDF 设计用于处理高熵输入密钥材料，
//! 如密码密钥、密钥协商协议的共享密钥或其他具有足够随机性的源。
//! 它们有效地从单个主密钥扩展或派生多个密钥。
//!
//! ## Supported Algorithms | 支持的算法
//!
//! ### HKDF (HMAC-based Key Derivation Function)
//! - **Standard**: RFC 5869
//! - **Type**: Extract-and-Expand KDF
//! - **Input**: High-entropy key material
//! - **Features**: Salt support, context information, variable output length
//!
//! ## HKDF Process | HKDF 过程
//!
//! HKDF operates in two phases:
//!
//! HKDF 分两个阶段运行：
//!
//! 1. **Extract Phase**: `PRK = HKDF-Extract(salt, IKM)`
//!    - Extracts a pseudorandom key from input key material
//!    - 从输入密钥材料中提取伪随机密钥
//!
//! 2. **Expand Phase**: `OKM = HKDF-Expand(PRK, info, L)`
//!    - Expands the PRK to desired output length
//!    - 将 PRK 扩展到所需的输出长度
//!
//! ## Security Properties | 安全属性
//!
//! - **Pseudorandomness**: Output is indistinguishable from random
//! - **Key Separation**: Different contexts produce independent keys
//! - **Forward Security**: Compromise of derived keys doesn't affect others
//! - **Efficiency**: Fast computation suitable for real-time applications
//!
//! - **伪随机性**: 输出与随机数据无法区分
//! - **密钥分离**: 不同上下文产生独立的密钥
//! - **前向安全**: 派生密钥的泄露不影响其他密钥
//! - **效率**: 适用于实时应用的快速计算
//!
//! ## Usage Guidelines | 使用指南
//!
//! - **Input Requirements**: Use only high-entropy key material (≥128 bits entropy)
//! - **Salt Usage**: Use unique salts when possible for key separation
//! - **Context Information**: Include application-specific context for domain separation
//! - **Output Length**: Request only the amount of key material needed
//!
//! - **输入要求**: 仅使用高熵密钥材料（≥128 位熵）
//! - **盐的使用**: 尽可能使用唯一盐进行密钥分离
//! - **上下文信息**: 包含应用特定上下文进行域分离
//! - **输出长度**: 仅请求所需的密钥材料数量

use crate::algorithms::HashAlgorithmEnum;
use bincode::{Decode, Encode};

/// Key-based Key Derivation Function algorithm enumeration.
///
/// 基于密钥的密钥派生函数算法枚举。
///
/// ## Algorithm Selection | 算法选择
///
/// Choose the hash function based on your security requirements:
/// - **HKDF-SHA256**: Standard choice, good performance, 128-bit security
/// - **HKDF-SHA384**: Higher security margin, 192-bit security
/// - **HKDF-SHA512**: Maximum security, 256-bit security
///
/// 根据您的安全要求选择哈希函数：
/// - **HKDF-SHA256**: 标准选择，良好性能，128 位安全性
/// - **HKDF-SHA384**: 更高安全边际，192 位安全性
/// - **HKDF-SHA512**: 最大安全性，256 位安全性
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, serde::Serialize, serde::Deserialize,
)]
pub enum KdfKeyAlgorithm {
    /// HMAC-based Key Derivation Function with configurable hash algorithm.
    ///
    /// 具有可配置哈希算法的基于 HMAC 的密钥派生函数。
    ///
    /// ## Properties | 属性
    /// - **Standard**: RFC 5869
    /// - **Type**: Extract-and-Expand KDF
    /// - **Security**: Based on HMAC security
    /// - **Performance**: High (depends on hash function)
    ///
    /// ## Features | 特性
    /// - **Salt Support**: Optional salt for key separation
    /// - **Context Information**: Application-specific context data
    /// - **Variable Output**: Any desired output length
    /// - **Deterministic**: Same inputs always produce same output
    ///
    /// - **盐支持**: 用于密钥分离的可选盐
    /// - **上下文信息**: 应用特定的上下文数据
    /// - **可变输出**: 任何所需的输出长度
    /// - **确定性**: 相同输入总是产生相同输出
    Hkdf(HashAlgorithmEnum),
}

impl KdfKeyAlgorithm {
    /// Creates a new key-based KDF algorithm builder.
    ///
    /// 创建新的基于密钥的 KDF 算法构建器。
    ///
    /// ## Returns | 返回值
    ///
    /// A builder that provides access to different key-based KDF algorithms.
    /// Use the builder methods to select the specific hash function for HKDF.
    ///
    /// 提供访问不同基于密钥的 KDF 算法的构建器。
    /// 使用构建器方法为 HKDF 选择特定的哈希函数。
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::kdf::key::KdfKeyAlgorithm;
    ///
    /// let hkdf_sha256 = KdfKeyAlgorithm::build().hkdf_sha256();
    /// let hkdf_sha512 = KdfKeyAlgorithm::build().hkdf_sha512();
    /// ```
    pub fn build() -> KdfKeyAlgorithmBuilder {
        KdfKeyAlgorithmBuilder
    }
}

/// Builder for constructing key-based KDF algorithm instances.
///
/// 用于构建基于密钥的 KDF 算法实例的构建器。
///
/// ## Usage Pattern | 使用模式
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::kdf::key::KdfKeyAlgorithm;
///
/// // Different hash functions for different security levels
/// let hkdf_sha256 = KdfKeyAlgorithm::build().hkdf_sha256(); // 128-bit security
/// let hkdf_sha384 = KdfKeyAlgorithm::build().hkdf_sha384(); // 192-bit security
/// let hkdf_sha512 = KdfKeyAlgorithm::build().hkdf_sha512(); // 256-bit security
/// ```
///
/// ## Hash Function Selection | 哈希函数选择
///
/// The choice of hash function affects both security and performance:
/// - **SHA-256**: Fastest, suitable for most applications
/// - **SHA-384**: Good balance of security and performance
/// - **SHA-512**: Highest security, slower on 32-bit platforms
///
/// 哈希函数的选择影响安全性和性能：
/// - **SHA-256**: 最快，适用于大多数应用
/// - **SHA-384**: 安全性和性能的良好平衡
/// - **SHA-512**: 最高安全性，在 32 位平台上较慢
pub struct KdfKeyAlgorithmBuilder;

impl KdfKeyAlgorithmBuilder {
    /// Selects HKDF with SHA-256 hash function.
    ///
    /// 选择使用 SHA-256 哈希函数的 HKDF。
    ///
    /// ## Properties | 属性
    /// - **Hash Function**: SHA-256
    /// - **Security Level**: 128-bit
    /// - **Output Size**: Up to 255 × 32 = 8160 bytes
    /// - **Performance**: High
    ///
    /// ## Use Cases | 使用场景
    /// - General-purpose key derivation
    /// - TLS/SSL key derivation
    /// - Symmetric key expansion
    /// - Protocol key derivation
    ///
    /// - 通用密钥派生
    /// - TLS/SSL 密钥派生
    /// - 对称密钥扩展
    /// - 协议密钥派生
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::kdf::key::KdfKeyAlgorithm;
    ///
    /// let algorithm = KdfKeyAlgorithm::build().hkdf_sha256();
    /// let kdf = algorithm.into_kdf_key_wrapper();
    ///
    /// // Derive keys from master key
    /// let master_key = b"high-entropy-master-key-material";
    /// let salt = Some(b"unique-salt");
    /// let info = Some(b"application-context");
    /// let derived_key = kdf.derive_key(master_key, salt, info, 32)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn hkdf_sha256(self) -> KdfKeyAlgorithm {
        KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha256)
    }

    /// Selects HKDF with SHA-384 hash function.
    ///
    /// 选择使用 SHA-384 哈希函数的 HKDF。
    ///
    /// ## Properties | 属性
    /// - **Hash Function**: SHA-384
    /// - **Security Level**: 192-bit
    /// - **Output Size**: Up to 255 × 48 = 12240 bytes
    /// - **Performance**: Medium
    ///
    /// ## Use Cases | 使用场景
    /// Applications requiring higher security than SHA-256:
    /// - High-security protocols
    /// - Long-term key derivation
    /// - Government/military applications
    ///
    /// 需要比 SHA-256 更高安全性的应用：
    /// - 高安全性协议
    /// - 长期密钥派生
    /// - 政府/军事应用
    pub fn hkdf_sha384(self) -> KdfKeyAlgorithm {
        KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha384)
    }

    /// Selects HKDF with SHA-512 hash function.
    ///
    /// 选择使用 SHA-512 哈希函数的 HKDF。
    ///
    /// ## Properties | 属性
    /// - **Hash Function**: SHA-512
    /// - **Security Level**: 256-bit
    /// - **Output Size**: Up to 255 × 64 = 16320 bytes
    /// - **Performance**: Medium (fast on 64-bit platforms)
    ///
    /// ## Use Cases | 使用场景
    /// Maximum security applications:
    /// - Top-secret data protection
    /// - Long-term archival security
    /// - Future-proofing against advances
    ///
    /// 最大安全性应用：
    /// - 绝密数据保护
    /// - 长期档案安全
    /// - 防范技术进步的未来保护
    ///
    /// ## Performance Note | 性能注意
    /// SHA-512 is optimized for 64-bit platforms and may be slower on 32-bit systems.
    /// Consider SHA-256 for better performance on resource-constrained devices.
    ///
    /// SHA-512 针对 64 位平台优化，在 32 位系统上可能较慢。
    /// 在资源受限的设备上考虑使用 SHA-256 以获得更好的性能。
    pub fn hkdf_sha512(self) -> KdfKeyAlgorithm {
        KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha512)
    }
}

use crate::wrappers::kdf::key::KdfKeyWrapper;

impl KdfKeyAlgorithm {
    /// Converts the algorithm enum into a concrete wrapper implementation.
    ///
    /// 将算法枚举转换为具体的包装器实现。
    ///
    /// ## Purpose | 目的
    ///
    /// This method creates a wrapper that implements the key-based KDF algorithm trait,
    /// enabling actual cryptographic operations like key derivation from high-entropy
    /// input material with type safety guarantees.
    ///
    /// 此方法创建一个实现基于密钥的 KDF 算法 trait 的包装器，
    /// 启用实际的密码操作，如从高熵输入材料派生密钥，并提供类型安全保证。
    ///
    /// ## Returns | 返回值
    ///
    /// A `KdfKeyWrapper` that can perform:
    /// - Key derivation from high-entropy input
    /// - Salt-based key separation
    /// - Context-aware key derivation
    /// - Variable-length output generation
    ///
    /// 可以执行以下操作的 `KdfKeyWrapper`：
    /// - 从高熵输入派生密钥
    /// - 基于盐的密钥分离
    /// - 上下文感知的密钥派生
    /// - 可变长度输出生成
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::kdf::key::KdfKeyAlgorithm;
    ///
    /// let algorithm = KdfKeyAlgorithm::build().hkdf_sha256();
    /// let kdf = algorithm.into_kdf_key_wrapper();
    ///
    /// // Derive multiple keys from a master key
    /// let master_key = b"high-entropy-master-key-32-bytes";
    /// let salt = Some(b"application-salt");
    ///
    /// // Derive encryption key
    /// let enc_key = kdf.derive_key(
    ///     master_key,
    ///     salt,
    ///     Some(b"encryption"),
    ///     32
    /// )?;
    ///
    /// // Derive MAC key
    /// let mac_key = kdf.derive_key(
    ///     master_key,
    ///     salt,
    ///     Some(b"authentication"),
    ///     32
    /// )?;
    ///
    /// // Keys are different due to different context
    /// assert_ne!(enc_key, mac_key);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// ## Security Best Practices | 安全最佳实践
    ///
    /// When using the wrapper:
    /// 1. **High-Entropy Input**: Ensure input key material has sufficient entropy
    /// 2. **Unique Salts**: Use different salts for different applications
    /// 3. **Context Separation**: Use context info to separate different key purposes
    /// 4. **Appropriate Length**: Request only the key length you need
    ///
    /// 使用包装器时：
    /// 1. **高熵输入**: 确保输入密钥材料具有足够的熵
    /// 2. **唯一盐**: 为不同应用使用不同的盐
    /// 3. **上下文分离**: 使用上下文信息分离不同的密钥用途
    /// 4. **适当长度**: 仅请求您需要的密钥长度
    ///
    /// ## Input Requirements | 输入要求
    ///
    /// - **Key Material**: Should have at least 128 bits of entropy
    /// - **Salt**: Optional but recommended for key separation
    /// - **Context**: Application-specific information for domain separation
    /// - **Output Length**: Any length up to algorithm maximum
    ///
    /// - **密钥材料**: 应至少具有 128 位熵
    /// - **盐**: 可选但推荐用于密钥分离
    /// - **上下文**: 用于域分离的应用特定信息
    /// - **输出长度**: 算法最大值内的任何长度
    pub fn into_kdf_key_wrapper(self) -> KdfKeyWrapper {
        use crate::wrappers::kdf::key::{HkdfSha256Wrapper, HkdfSha384Wrapper, HkdfSha512Wrapper};
        match self {
            KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha256) => {
                KdfKeyWrapper::new(Box::new(HkdfSha256Wrapper::default()))
            }
            KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha384) => {
                KdfKeyWrapper::new(Box::new(HkdfSha384Wrapper::default()))
            }
            KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha512) => {
                KdfKeyWrapper::new(Box::new(HkdfSha512Wrapper::default()))
            }
        }
    }
}
