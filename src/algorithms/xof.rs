//! Extendable Output Functions (XOF) for variable-length cryptographic output.
//!
//! 用于可变长度密码输出的可扩展输出函数 (XOF)。
//!
//! ## Overview | 概述
//!
//! Extendable Output Functions (XOFs) are cryptographic functions that can produce
//! output of any desired length. Unlike traditional hash functions with fixed output
//! sizes, XOFs can generate arbitrarily long pseudorandom sequences from input data.
//!
//! 可扩展输出函数 (XOF) 是可以产生任何所需长度输出的密码函数。
//! 与具有固定输出大小的传统哈希函数不同，XOF 可以从输入数据生成任意长的伪随机序列。
//!
//! ## Use Cases | 使用场景
//!
//! - **Key Derivation**: Generate keys of specific lengths
//! - **Random Number Generation**: Produce cryptographically secure random data
//! - **Stream Ciphers**: Create keystreams for encryption
//! - **Mask Generation**: Generate masks for cryptographic protocols
//! - **Domain Separation**: Create distinct outputs for different contexts
//!
//! - **密钥派生**: 生成特定长度的密钥
//! - **随机数生成**: 产生密码学安全的随机数据
//! - **流密码**: 为加密创建密钥流
//! - **掩码生成**: 为密码协议生成掩码
//! - **域分离**: 为不同上下文创建不同的输出
//!
//! ## SHAKE Algorithm Family | SHAKE 算法族
//!
//! SHAKE functions are based on the Keccak sponge construction (same as SHA-3)
//! but with extendable output capability:
//!
//! SHAKE 函数基于 Keccak 海绵构造（与 SHA-3 相同），但具有可扩展输出能力：
//!
//! | Algorithm | Security Level | Rate | Capacity | Use Case |
//! |-----------|----------------|------|----------|----------|
//! | SHAKE-128 | 128-bit | 1344 bits | 256 bits | General purpose |
//! | SHAKE-256 | 256-bit | 1088 bits | 512 bits | High security |
//!
//! ## Security Properties | 安全属性
//!
//! - **Pseudorandomness**: Output is indistinguishable from random
//! - **Collision Resistance**: Infeasible to find two inputs with same output
//! - **Preimage Resistance**: Given output, infeasible to find input
//! - **Domain Separation**: Different contexts produce independent outputs
//!
//! - **伪随机性**: 输出与随机数据无法区分
//! - **抗碰撞性**: 找到具有相同输出的两个输入在计算上不可行
//! - **原像抗性**: 给定输出，找到输入在计算上不可行
//! - **域分离**: 不同上下文产生独立的输出

use crate::bincode::{Decode, Encode};

/// Extendable Output Function algorithm enumeration.
///
/// 可扩展输出函数算法枚举。
///
/// ## Algorithm Selection | 算法选择
///
/// Choose based on your security requirements:
/// - **SHAKE-128**: For general-purpose applications requiring 128-bit security
/// - **SHAKE-256**: For high-security applications requiring 256-bit security
///
/// 根据您的安全要求选择：
/// - **SHAKE-128**: 用于需要 128 位安全性的通用应用
/// - **SHAKE-256**: 用于需要 256 位安全性的高安全性应用
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, serde::Serialize, serde::Deserialize,
)]
pub enum XofAlgorithm {
    /// SHAKE family of extendable output functions.
    ///
    /// SHAKE 可扩展输出函数族。
    ///
    /// Based on the Keccak sponge construction, providing variable-length output
    /// with strong security guarantees. Standardized in FIPS 202.
    ///
    /// 基于 Keccak 海绵构造，提供具有强安全保证的可变长度输出。
    /// 在 FIPS 202 中标准化。
    Shake(ShakeVariant),
}

/// SHAKE algorithm variants with different security levels.
///
/// 具有不同安全级别的 SHAKE 算法变体。
///
/// ## Performance vs Security | 性能与安全性
///
/// SHAKE-128 offers better performance while SHAKE-256 provides higher security.
/// Both are suitable for most applications, with the choice depending on
/// specific security requirements.
///
/// SHAKE-128 提供更好的性能，而 SHAKE-256 提供更高的安全性。
/// 两者都适用于大多数应用，选择取决于特定的安全要求。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, serde::Serialize, serde::Deserialize,
)]
pub enum ShakeVariant {
    /// SHAKE-128: 128-bit security level.
    ///
    /// SHAKE-128: 128 位安全级别。
    ///
    /// ## Properties | 属性
    /// - Security level: 128-bit
    /// - Rate: 1344 bits (168 bytes)
    /// - Capacity: 256 bits (32 bytes)
    /// - Performance: High
    ///
    /// ## Use Cases | 使用场景
    /// Suitable for most applications requiring variable-length output.
    /// Recommended for general-purpose key derivation and random generation.
    ///
    /// 适用于大多数需要可变长度输出的应用。
    /// 推荐用于通用密钥派生和随机生成。
    V128,

    /// SHAKE-256: 256-bit security level.
    ///
    /// SHAKE-256: 256 位安全级别。
    ///
    /// ## Properties | 属性
    /// - Security level: 256-bit
    /// - Rate: 1088 bits (136 bytes)
    /// - Capacity: 512 bits (64 bytes)
    /// - Performance: Medium
    ///
    /// ## Use Cases | 使用场景
    /// For applications requiring higher security margins or long-term protection.
    /// Recommended for high-value or sensitive applications.
    ///
    /// 用于需要更高安全边际或长期保护的应用。
    /// 推荐用于高价值或敏感应用。
    V256,
}

impl XofAlgorithm {
    /// Creates a new XOF algorithm builder.
    ///
    /// 创建新的 XOF 算法构建器。
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::xof::XofAlgorithm;
    ///
    /// let shake128 = XofAlgorithm::build().shake128();
    /// let shake256 = XofAlgorithm::build().shake256();
    /// ```
    pub fn build() -> XofAlgorithmBuilder {
        XofAlgorithmBuilder
    }
}

/// Builder for constructing XOF algorithm instances.
///
/// 用于构建 XOF 算法实例的构建器。
///
/// ## Usage Pattern | 使用模式
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::xof::XofAlgorithm;
///
/// // For general-purpose applications
/// let shake128 = XofAlgorithm::build().shake128();
///
/// // For high-security applications
/// let shake256 = XofAlgorithm::build().shake256();
/// ```
///
/// ## Performance Considerations | 性能考虑
///
/// SHAKE-128 is faster due to its higher rate (more data processed per round),
/// while SHAKE-256 provides higher security at the cost of some performance.
///
/// SHAKE-128 由于其更高的速率（每轮处理更多数据）而更快，
/// 而 SHAKE-256 以一些性能为代价提供更高的安全性。
pub struct XofAlgorithmBuilder;

impl XofAlgorithmBuilder {
    /// Selects SHAKE-128 extendable output function.
    ///
    /// 选择 SHAKE-128 可扩展输出函数。
    ///
    /// ## Properties | 属性
    /// - Security level: 128-bit
    /// - Rate: 1344 bits (168 bytes per round)
    /// - Capacity: 256 bits
    /// - Performance: High
    ///
    /// ## Use Cases | 使用场景
    /// - General-purpose key derivation
    /// - Random number generation
    /// - Stream cipher keystreams
    /// - Mask generation functions
    ///
    /// - 通用密钥派生
    /// - 随机数生成
    /// - 流密码密钥流
    /// - 掩码生成函数
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::xof::XofAlgorithm;
    /// use seal_crypto_wrapper::prelude::XofAlgorithmTrait;
    ///
    /// let xof = XofAlgorithm::build().shake128();
    /// let wrapper = xof.into_wrapper();
    ///
    /// // Generate variable-length output
    /// let mut reader = wrapper.reader(b"input data", None, None)?;
    /// let output = reader.read_boxed(32); // 32 bytes of output
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn shake128(self) -> XofAlgorithm {
        XofAlgorithm::Shake(ShakeVariant::V128)
    }

    /// Selects SHAKE-256 extendable output function.
    ///
    /// 选择 SHAKE-256 可扩展输出函数。
    ///
    /// ## Properties | 属性
    /// - Security level: 256-bit
    /// - Rate: 1088 bits (136 bytes per round)
    /// - Capacity: 512 bits
    /// - Performance: Medium
    ///
    /// ## Use Cases | 使用场景
    /// - High-security key derivation
    /// - Long-term cryptographic applications
    /// - Post-quantum security preparations
    /// - High-value data protection
    ///
    /// - 高安全性密钥派生
    /// - 长期密码应用
    /// - 后量子安全准备
    /// - 高价值数据保护
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::xof::XofAlgorithm;
    /// use seal_crypto_wrapper::prelude::XofAlgorithmTrait;
    ///
    /// let xof = XofAlgorithm::build().shake256();
    /// let wrapper = xof.into_wrapper();
    ///
    /// // Generate large amounts of pseudorandom data
    /// let mut reader = wrapper.reader(b"seed", Some(b"salt"), Some(b"info"))?;
    /// let large_output = reader.read_boxed(1024); // 1KB of output
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn shake256(self) -> XofAlgorithm {
        XofAlgorithm::Shake(ShakeVariant::V256)
    }
}

use crate::wrappers::xof::XofWrapper;

impl XofAlgorithm {
    /// Converts the algorithm enum into a concrete wrapper implementation.
    ///
    /// 将算法枚举转换为具体的包装器实现。
    ///
    /// ## Purpose | 目的
    ///
    /// This method creates a wrapper that implements the XOF algorithm trait,
    /// enabling actual cryptographic operations with variable-length output
    /// generation capabilities.
    ///
    /// 此方法创建一个实现 XOF 算法 trait 的包装器，
    /// 启用具有可变长度输出生成能力的实际密码操作。
    ///
    /// ## Returns | 返回值
    ///
    /// An `XofWrapper` that can:
    /// - Create readers for streaming output
    /// - Generate arbitrary-length pseudorandom data
    /// - Support domain separation with salt and info parameters
    /// - Provide algorithm introspection
    ///
    /// 可以执行以下操作的 `XofWrapper`：
    /// - 为流式输出创建读取器
    /// - 生成任意长度的伪随机数据
    /// - 支持使用盐和信息参数的域分离
    /// - 提供算法内省
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::xof::XofAlgorithm;
    /// use seal_crypto_wrapper::prelude::XofAlgorithmTrait;
    ///
    /// let algorithm = XofAlgorithm::build().shake128();
    /// let xof = algorithm.into_wrapper();
    ///
    /// // Create a reader with input key material
    /// let mut reader = xof.reader(
    ///     b"input_key_material",
    ///     Some(b"optional_salt"),
    ///     Some(b"context_info")
    /// )?;
    ///
    /// // Read different amounts of data
    /// let key1 = reader.read_boxed(32);  // 32-byte key
    /// let key2 = reader.read_boxed(16);  // 16-byte key
    /// let nonce = reader.read_boxed(12); // 12-byte nonce
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn into_wrapper(self) -> XofWrapper {
        use crate::wrappers::xof::{Shake128Wrapper, Shake256Wrapper};
        match self {
            XofAlgorithm::Shake(ShakeVariant::V128) => {
                XofWrapper::new(Box::new(Shake128Wrapper::default()))
            }
            XofAlgorithm::Shake(ShakeVariant::V256) => {
                XofWrapper::new(Box::new(Shake256Wrapper::default()))
            }
        }
    }
}
