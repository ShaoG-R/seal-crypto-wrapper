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
pub enum HashAlgorithm {
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

impl HashAlgorithm {
    /// Creates a new hash algorithm builder.
    ///
    /// 创建新的哈希算法构建器。
    ///
    /// # Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::hash::HashAlgorithm;
    ///
    /// let algorithm = HashAlgorithm::build().sha256();
    /// ```
    pub fn build() -> HashAlgorithmBuilder {
        HashAlgorithmBuilder
    }
}

/// Builder for constructing hash algorithm instances.
///
/// 用于构建哈希算法实例的构建器。
///
/// ## Usage Pattern | 使用模式
///
/// The builder provides a fluent interface for algorithm selection:
///
/// 构建器为算法选择提供流畅的接口：
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::hash::HashAlgorithm;
///
/// // General purpose
/// let sha256 = HashAlgorithm::build().sha256();
///
/// // High security
/// let sha384 = HashAlgorithm::build().sha384();
///
/// // Maximum security
/// let sha512 = HashAlgorithm::build().sha512();
/// ```
pub struct HashAlgorithmBuilder;

impl HashAlgorithmBuilder {
    /// Selects SHA-256 algorithm.
    ///
    /// 选择 SHA-256 算法。
    ///
    /// ## Properties | 属性
    /// - Output size: 256 bits (32 bytes)
    /// - Security level: 128-bit
    ///
    /// ## Use Cases | 使用场景
    /// - Digital signatures
    /// - HMACs
    /// - General data integrity
    pub fn sha256(self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }

    /// Selects SHA-384 algorithm.
    ///
    /// 选择 SHA-384 算法。
    ///
    /// ## Properties | 属性
    /// - Output size: 384 bits (48 bytes)
    /// - Security level: 192-bit
    ///
    /// ## Use Cases | 使用场景
    /// - Applications requiring higher security than SHA-256
    /// - Compliance with specific security standards
    pub fn sha384(self) -> HashAlgorithm {
        HashAlgorithm::Sha384
    }

    /// Selects SHA-512 algorithm.
    ///
    /// 选择 SHA-512 算法。
    ///
    /// ## Properties | 属性
    /// - Output size: 512 bits (64 bytes)
    /// - Security level: 256-bit
    ///
    /// ## Use Cases | 使用场景
    /// - Long-term data protection
    /// - Maximum security applications
    /// - Optimized for 64-bit platforms
    pub fn sha512(self) -> HashAlgorithm {
        HashAlgorithm::Sha512
    }
}

use crate::wrappers::hash::HashAlgorithmWrapper;

impl HashAlgorithm {
    /// Converts the algorithm enum into a concrete wrapper implementation.
    ///
    /// 将算法枚举转换为具体的包装器实现。
    ///
    /// ## Purpose | 目的
    ///
    /// This method bridges the gap between algorithm selection and actual cryptographic
    /// operations. It returns a wrapper that implements the hash algorithm trait.
    ///
    /// 此方法在算法选择和实际密码操作之间架起桥梁。
    /// 它返回一个实现哈希算法 trait 的包装器。
    ///
    /// ## Returns | 返回值
    ///
    /// A `HashAlgorithmWrapper` that can perform:
    /// - Hashing
    /// - HMAC computation
    ///
    /// 可以执行以下操作的 `HashAlgorithmWrapper`：
    /// - 哈希计算
    /// - HMAC 计算
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::hash::HashAlgorithm;
    ///
    /// let algorithm = HashAlgorithm::build().sha256();
    /// let hasher = algorithm.into_wrapper();
    ///
    /// // Now you can use the hasher
    /// let digest = hasher.hash(b"hello world");
    /// ```
    pub fn into_wrapper(self) -> HashAlgorithmWrapper {
        use crate::wrappers::hash::{Hash256Wrapper, Hash384Wrapper, Hash512Wrapper};
        match self {
            HashAlgorithm::Sha256 => HashAlgorithmWrapper::new(Box::new(Hash256Wrapper::default())),
            HashAlgorithm::Sha384 => HashAlgorithmWrapper::new(Box::new(Hash384Wrapper::default())),
            HashAlgorithm::Sha512 => HashAlgorithmWrapper::new(Box::new(Hash512Wrapper::default())),
        }
    }
}
