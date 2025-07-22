//! Key Encapsulation Mechanism (KEM) algorithms.
//!
//! 密钥封装机制 (KEM) 算法。
//!
//! ## Overview | 概述
//!
//! Key Encapsulation Mechanisms (KEMs) are cryptographic algorithms used to securely
//! establish shared secrets between parties. They are essential components of hybrid
//! encryption schemes and post-quantum cryptography.
//!
//! 密钥封装机制 (KEM) 是用于在各方之间安全建立共享密钥的密码算法。
//! 它们是混合加密方案和后量子密码学的重要组成部分。
//!
//! ## Algorithm Comparison | 算法对比
//!
//! | Algorithm | Type | Security Level | Key Size | Ciphertext Size | Performance |
//! |-----------|------|----------------|----------|-----------------|-------------|
//! | RSA-2048  | Traditional | 112-bit | 2048-bit | ~256 bytes | Medium |
//! | RSA-4096  | Traditional | 128-bit | 4096-bit | ~512 bytes | Slow |
//! | Kyber-512 | Post-Quantum | 128-bit | ~800 bytes | ~768 bytes | Fast |
//! | Kyber-768 | Post-Quantum | 192-bit | ~1184 bytes | ~1088 bytes | Fast |
//! | Kyber-1024| Post-Quantum | 256-bit | ~1568 bytes | ~1568 bytes | Fast |
//!
//! ## Usage Recommendations | 使用建议
//!
//! - **Current Applications**: RSA-2048 or RSA-4096 for compatibility
//! - **Future-Proofing**: Kyber variants for post-quantum security
//! - **High Performance**: Kyber-512 for most applications
//! - **Maximum Security**: Kyber-1024 for long-term protection
//!
//! - **当前应用**: RSA-2048 或 RSA-4096 用于兼容性
//! - **面向未来**: Kyber 变体用于后量子安全
//! - **高性能**: Kyber-512 适用于大多数应用
//! - **最大安全性**: Kyber-1024 用于长期保护

use crate::algorithms::HashAlgorithmEnum;
use crate::wrappers::asymmetric::kem::KemAlgorithmWrapper;
use bincode::{Decode, Encode};

/// Key Encapsulation Mechanism algorithm enumeration.
///
/// 密钥封装机制算法枚举。
///
/// ## Algorithm Types | 算法类型
///
/// This enum supports both traditional and post-quantum KEM algorithms,
/// allowing applications to choose based on their security and compatibility requirements.
///
/// 此枚举支持传统和后量子 KEM 算法，
/// 允许应用程序根据其安全性和兼容性要求进行选择。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, serde::Serialize, serde::Deserialize,
)]
pub enum KemAlgorithm {
    /// RSA-based Key Encapsulation Mechanism.
    ///
    /// 基于 RSA 的密钥封装机制。
    ///
    /// Traditional public-key cryptosystem with configurable key size and hash function.
    /// Widely supported but vulnerable to quantum attacks.
    ///
    /// 具有可配置密钥大小和哈希函数的传统公钥密码系统。
    /// 广泛支持但易受量子攻击。
    Rsa(RsaBits, HashAlgorithmEnum),

    /// Kyber post-quantum Key Encapsulation Mechanism.
    ///
    /// Kyber 后量子密钥封装机制。
    ///
    /// NIST-standardized lattice-based KEM providing security against quantum computers.
    /// Offers excellent performance and smaller ciphertext sizes compared to RSA.
    ///
    /// NIST 标准化的基于格的 KEM，提供对量子计算机的安全性。
    /// 与 RSA 相比提供出色的性能和更小的密文大小。
    Kyber(KyberSecurityLevel),
}

/// RSA key size variants for KEM operations.
///
/// 用于 KEM 操作的 RSA 密钥大小变体。
///
/// ## Security Considerations | 安全考虑
///
/// - **2048-bit**: Minimum recommended size, 112-bit security level
/// - **4096-bit**: Higher security margin, 128-bit security level
///
/// - **2048 位**: 最小推荐大小，112 位安全级别
/// - **4096 位**: 更高安全边际，128 位安全级别
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, serde::Serialize, serde::Deserialize,
)]
pub enum RsaBits {
    /// 2048-bit RSA keys (112-bit security level).
    ///
    /// 2048 位 RSA 密钥（112 位安全级别）。
    ///
    /// Minimum recommended size for new applications.
    /// Provides adequate security for most current use cases.
    ///
    /// 新应用的最小推荐大小。
    /// 为大多数当前用例提供足够的安全性。
    B2048,

    /// 4096-bit RSA keys (128-bit security level).
    ///
    /// 4096 位 RSA 密钥（128 位安全级别）。
    ///
    /// Higher security margin at the cost of performance.
    /// Recommended for high-value or long-term applications.
    ///
    /// 以性能为代价提供更高的安全边际。
    /// 推荐用于高价值或长期应用。
    B4096,
}

/// Kyber security level variants.
///
/// Kyber 安全级别变体。
///
/// ## NIST Security Categories | NIST 安全类别
///
/// These correspond to NIST post-quantum cryptography security categories:
/// - Level 1: Equivalent to AES-128
/// - Level 3: Equivalent to AES-192
/// - Level 5: Equivalent to AES-256
///
/// 这些对应于 NIST 后量子密码学安全类别：
/// - 级别 1: 等同于 AES-128
/// - 级别 3: 等同于 AES-192
/// - 级别 5: 等同于 AES-256
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, serde::Serialize, serde::Deserialize,
)]
pub enum KyberSecurityLevel {
    /// Kyber-512: NIST security category 1 (128-bit security).
    ///
    /// Kyber-512: NIST 安全类别 1（128 位安全性）。
    ///
    /// Recommended for most applications requiring post-quantum security.
    /// Offers the best performance-to-security ratio.
    ///
    /// 推荐用于大多数需要后量子安全的应用。
    /// 提供最佳的性能与安全性比率。
    L512,

    /// Kyber-768: NIST security category 3 (192-bit security).
    ///
    /// Kyber-768: NIST 安全类别 3（192 位安全性）。
    ///
    /// Higher security level for applications with elevated security requirements.
    /// Balanced performance and security.
    ///
    /// 为具有更高安全要求的应用提供更高的安全级别。
    /// 平衡的性能和安全性。
    L768,

    /// Kyber-1024: NIST security category 5 (256-bit security).
    ///
    /// Kyber-1024: NIST 安全类别 5（256 位安全性）。
    ///
    /// Maximum security level for the most sensitive applications.
    /// Recommended for long-term data protection.
    ///
    /// 最敏感应用的最大安全级别。
    /// 推荐用于长期数据保护。
    L1024,
}

/// Builder for constructing KEM algorithm instances.
///
/// 用于构建 KEM 算法实例的构建器。
///
/// ## Usage Pattern | 使用模式
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::asymmetric::kem::KemAlgorithm;
///
/// // Post-quantum algorithms (recommended)
/// let kyber512 = KemAlgorithm::build().kyber512();
/// let kyber768 = KemAlgorithm::build().kyber768();
///
/// // Traditional algorithms (for compatibility)
/// let rsa = KemAlgorithm::build().rsa2048().sha256();
/// ```
pub struct KemAlgorithmBuilder;

impl KemAlgorithmBuilder {
    /// Selects RSA-2048 for KEM operations.
    ///
    /// 选择 RSA-2048 进行 KEM 操作。
    ///
    /// ## Properties | 属性
    /// - Key size: 2048 bits
    /// - Security level: 112-bit (classical)
    /// - Performance: Medium
    /// - Quantum resistance: No
    ///
    /// ## Next Step | 下一步
    /// Choose a hash function: `.sha256()`, `.sha384()`, or `.sha512()`
    ///
    /// 选择哈希函数：`.sha256()`、`.sha384()` 或 `.sha512()`
    pub fn rsa2048(self) -> RsaBuilder {
        RsaBuilder {
            bits: RsaBits::B2048,
        }
    }

    /// Selects RSA-4096 for KEM operations.
    ///
    /// 选择 RSA-4096 进行 KEM 操作。
    ///
    /// ## Properties | 属性
    /// - Key size: 4096 bits
    /// - Security level: 128-bit (classical)
    /// - Performance: Slow
    /// - Quantum resistance: No
    ///
    /// ## Use Cases | 使用场景
    /// High-security applications requiring larger RSA keys.
    /// 需要更大 RSA 密钥的高安全性应用。
    pub fn rsa4096(self) -> RsaBuilder {
        RsaBuilder {
            bits: RsaBits::B4096,
        }
    }

    /// Selects Kyber-512 post-quantum KEM.
    ///
    /// 选择 Kyber-512 后量子 KEM。
    ///
    /// ## Properties | 属性
    /// - Security level: 128-bit (post-quantum)
    /// - Public key size: ~800 bytes
    /// - Ciphertext size: ~768 bytes
    /// - Performance: Fast
    /// - Quantum resistance: Yes
    ///
    /// ## Recommendation | 推荐
    /// Best choice for most applications requiring post-quantum security.
    /// 大多数需要后量子安全的应用的最佳选择。
    pub fn kyber512(self) -> KemAlgorithm {
        KemAlgorithm::Kyber(KyberSecurityLevel::L512)
    }

    /// Selects Kyber-768 post-quantum KEM.
    ///
    /// 选择 Kyber-768 后量子 KEM。
    ///
    /// ## Properties | 属性
    /// - Security level: 192-bit (post-quantum)
    /// - Public key size: ~1184 bytes
    /// - Ciphertext size: ~1088 bytes
    /// - Performance: Fast
    /// - Quantum resistance: Yes
    ///
    /// ## Use Cases | 使用场景
    /// Applications requiring higher security than Kyber-512.
    /// 需要比 Kyber-512 更高安全性的应用。
    pub fn kyber768(self) -> KemAlgorithm {
        KemAlgorithm::Kyber(KyberSecurityLevel::L768)
    }

    /// Selects Kyber-1024 post-quantum KEM.
    ///
    /// 选择 Kyber-1024 后量子 KEM。
    ///
    /// ## Properties | 属性
    /// - Security level: 256-bit (post-quantum)
    /// - Public key size: ~1568 bytes
    /// - Ciphertext size: ~1568 bytes
    /// - Performance: Fast
    /// - Quantum resistance: Yes
    ///
    /// ## Use Cases | 使用场景
    /// Maximum security for long-term data protection.
    /// 长期数据保护的最大安全性。
    pub fn kyber1024(self) -> KemAlgorithm {
        KemAlgorithm::Kyber(KyberSecurityLevel::L1024)
    }
}

/// Builder for RSA KEM algorithms with hash function selection.
///
/// 用于选择哈希函数的 RSA KEM 算法构建器。
///
/// ## Hash Function Selection | 哈希函数选择
///
/// The hash function affects both security and performance:
/// - SHA-256: Standard choice, good performance
/// - SHA-384: Higher security, medium performance
/// - SHA-512: Maximum security, slower performance
///
/// 哈希函数影响安全性和性能：
/// - SHA-256: 标准选择，良好性能
/// - SHA-384: 更高安全性，中等性能
/// - SHA-512: 最大安全性，较慢性能
pub struct RsaBuilder {
    bits: RsaBits,
}

impl RsaBuilder {
    /// Uses SHA-256 hash function with RSA KEM.
    ///
    /// 在 RSA KEM 中使用 SHA-256 哈希函数。
    ///
    /// ## Properties | 属性
    /// - Hash output: 256 bits
    /// - Security level: 128-bit
    /// - Performance: High
    /// - Compatibility: Excellent
    ///
    /// ## Recommendation | 推荐
    /// Standard choice for most RSA KEM applications.
    /// 大多数 RSA KEM 应用的标准选择。
    pub fn sha256(self) -> KemAlgorithm {
        KemAlgorithm::Rsa(self.bits, HashAlgorithmEnum::Sha256)
    }

    /// Uses SHA-384 hash function with RSA KEM.
    ///
    /// 在 RSA KEM 中使用 SHA-384 哈希函数。
    ///
    /// ## Properties | 属性
    /// - Hash output: 384 bits
    /// - Security level: 192-bit
    /// - Performance: Medium
    /// - Use case: Higher security requirements
    ///
    /// 使用场景：更高的安全要求
    pub fn sha384(self) -> KemAlgorithm {
        KemAlgorithm::Rsa(self.bits, HashAlgorithmEnum::Sha384)
    }

    /// Uses SHA-512 hash function with RSA KEM.
    ///
    /// 在 RSA KEM 中使用 SHA-512 哈希函数。
    ///
    /// ## Properties | 属性
    /// - Hash output: 512 bits
    /// - Security level: 256-bit
    /// - Performance: Lower
    /// - Use case: Maximum security applications
    ///
    /// 使用场景：最大安全性应用
    pub fn sha512(self) -> KemAlgorithm {
        KemAlgorithm::Rsa(self.bits, HashAlgorithmEnum::Sha512)
    }
}

impl KemAlgorithm {
    /// Creates a new KEM algorithm builder.
    ///
    /// 创建新的 KEM 算法构建器。
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::asymmetric::kem::KemAlgorithm;
    ///
    /// // Post-quantum KEM
    /// let kyber = KemAlgorithm::build().kyber512();
    ///
    /// // Traditional KEM
    /// let rsa = KemAlgorithm::build().rsa2048().sha256();
    /// ```
    pub fn build() -> KemAlgorithmBuilder {
        KemAlgorithmBuilder
    }
}

impl KemAlgorithm {
    /// Converts the algorithm enum into a concrete wrapper implementation.
    ///
    /// 将算法枚举转换为具体的包装器实现。
    ///
    /// ## Purpose | 目的
    ///
    /// This method creates a wrapper that implements the KEM algorithm trait,
    /// enabling actual cryptographic operations like key encapsulation and
    /// decapsulation with type safety guarantees.
    ///
    /// 此方法创建一个实现 KEM 算法 trait 的包装器，
    /// 启用实际的密码操作，如密钥封装和解封装，并提供类型安全保证。
    ///
    /// ## Returns | 返回值
    ///
    /// A `KemAlgorithmWrapper` that can perform:
    /// - Key pair generation
    /// - Key encapsulation (encryption)
    /// - Key decapsulation (decryption)
    /// - Algorithm introspection
    ///
    /// 可以执行以下操作的 `KemAlgorithmWrapper`：
    /// - 密钥对生成
    /// - 密钥封装（加密）
    /// - 密钥解封装（解密）
    /// - 算法内省
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::asymmetric::kem::KemAlgorithm;
    ///
    /// let algorithm = KemAlgorithm::build().kyber512();
    /// let kem = algorithm.into_kem_wrapper();
    ///
    /// // Generate key pair
    /// let keypair = kem.generate_keypair()?;
    /// let (public_key, private_key) = keypair.into_keypair();
    ///
    /// // Encapsulate a shared secret
    /// let (shared_secret, ciphertext) = kem.encapsulate_key(&public_key)?;
    ///
    /// // Decapsulate to recover the shared secret
    /// let recovered_secret = kem.decapsulate_key(&private_key, &ciphertext)?;
    /// assert_eq!(shared_secret, recovered_secret);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn into_kem_wrapper(self) -> KemAlgorithmWrapper {
        use crate::algorithms::HashAlgorithmEnum;
        use crate::wrappers::asymmetric::kem::{
            KemAlgorithmWrapper, Kyber512Wrapper, Kyber768Wrapper, Kyber1024Wrapper,
            Rsa2048Sha256Wrapper, Rsa2048Sha384Wrapper, Rsa2048Sha512Wrapper, Rsa4096Sha256Wrapper,
            Rsa4096Sha384Wrapper, Rsa4096Sha512Wrapper,
        };
        match self {
            KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha256) => {
                KemAlgorithmWrapper::new(Box::new(Rsa2048Sha256Wrapper::default()))
            }
            KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha384) => {
                KemAlgorithmWrapper::new(Box::new(Rsa2048Sha384Wrapper::default()))
            }
            KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha512) => {
                KemAlgorithmWrapper::new(Box::new(Rsa2048Sha512Wrapper::default()))
            }
            KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha256) => {
                KemAlgorithmWrapper::new(Box::new(Rsa4096Sha256Wrapper::default()))
            }
            KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha384) => {
                KemAlgorithmWrapper::new(Box::new(Rsa4096Sha384Wrapper::default()))
            }
            KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha512) => {
                KemAlgorithmWrapper::new(Box::new(Rsa4096Sha512Wrapper::default()))
            }
            KemAlgorithm::Kyber(KyberSecurityLevel::L512) => {
                KemAlgorithmWrapper::new(Box::new(Kyber512Wrapper::default()))
            }
            KemAlgorithm::Kyber(KyberSecurityLevel::L768) => {
                KemAlgorithmWrapper::new(Box::new(Kyber768Wrapper::default()))
            }
            KemAlgorithm::Kyber(KyberSecurityLevel::L1024) => {
                KemAlgorithmWrapper::new(Box::new(Kyber1024Wrapper::default()))
            }
        }
    }
}
