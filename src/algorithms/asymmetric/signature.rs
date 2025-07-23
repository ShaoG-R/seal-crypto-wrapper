//! Digital signature algorithms for authentication and non-repudiation.
//!
//! 用于认证和不可否认性的数字签名算法。
//!
//! ## Overview | 概述
//!
//! Digital signature algorithms provide authentication, data integrity, and non-repudiation
//! through public-key cryptography. A digital signature proves that a message was created
//! by the holder of a private key, without revealing the private key itself.
//!
//! 数字签名算法通过公钥密码学提供认证、数据完整性和不可否认性。
//! 数字签名证明消息是由私钥持有者创建的，而不会泄露私钥本身。
//!
//! ## Supported Algorithms | 支持的算法
//!
//! ### Traditional Algorithms | 传统算法
//!
//! #### Ed25519 (Edwards Curve Digital Signature Algorithm)
//! - **Security Level**: 128-bit
//! - **Key Size**: 32 bytes (public), 32 bytes (private)
//! - **Signature Size**: 64 bytes
//! - **Performance**: Very high
//! - **Features**: Deterministic, no hash function needed
//!
//! #### ECDSA P-256 (Elliptic Curve Digital Signature Algorithm)
//! - **Security Level**: 128-bit
//! - **Key Size**: 32 bytes (public), 32 bytes (private)
//! - **Signature Size**: ~64 bytes (variable)
//! - **Performance**: High
//! - **Standardization**: NIST FIPS 186-4, widely supported
//!
//! ### Post-Quantum Algorithms | 后量子算法
//!
//! #### Dilithium (Lattice-based signatures)
//! - **Type**: Post-quantum secure
//! - **Security**: Based on lattice problems
//! - **NIST Status**: Standardized (FIPS 204)
//! - **Variants**: Dilithium-2, Dilithium-3, Dilithium-5
//!
//! ## Algorithm Comparison | 算法对比
//!
//! | Algorithm | Security | Key Size | Signature Size | Performance | Quantum Safe |
//! |-----------|----------|----------|----------------|-------------|--------------|
//! | Ed25519   | 128-bit  | 64 bytes | 64 bytes       | Very High   | No           |
//! | ECDSA P-256| 128-bit | 64 bytes | ~64 bytes      | High        | No           |
//! | Dilithium-2| 128-bit | ~2.5KB   | ~2.4KB         | Medium      | Yes          |
//! | Dilithium-3| 192-bit | ~4KB     | ~3.3KB         | Medium      | Yes          |
//! | Dilithium-5| 256-bit | ~4.9KB   | ~4.6KB         | Medium      | Yes          |
//!
//! ## Security Considerations | 安全考虑
//!
//! - **Private Key Protection**: Private keys must be kept absolutely secret
//! - **Randomness Quality**: Use high-quality random number generation
//! - **Hash Function**: Use appropriate hash functions for message digests
//! - **Signature Verification**: Always verify signatures before trusting data
//! - **Key Rotation**: Implement regular key rotation policies
//!
//! - **私钥保护**: 私钥必须绝对保密
//! - **随机性质量**: 使用高质量的随机数生成
//! - **哈希函数**: 为消息摘要使用适当的哈希函数
//! - **签名验证**: 在信任数据之前始终验证签名
//! - **密钥轮换**: 实施定期密钥轮换策略

use bincode::{Decode, Encode};

/// Dilithium security level variants.
///
/// Dilithium 安全级别变体。
///
/// ## NIST Security Categories | NIST 安全类别
///
/// These correspond to NIST post-quantum cryptography security categories:
/// - Level 2: Equivalent to AES-128 (128-bit security)
/// - Level 3: Equivalent to AES-192 (192-bit security)
/// - Level 5: Equivalent to AES-256 (256-bit security)
///
/// 这些对应于 NIST 后量子密码学安全类别：
/// - 级别 2: 等同于 AES-128（128 位安全性）
/// - 级别 3: 等同于 AES-192（192 位安全性）
/// - 级别 5: 等同于 AES-256（256 位安全性）
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, serde::Serialize, serde::Deserialize,
)]
pub enum DilithiumSecurityLevel {
    /// Dilithium-2: NIST security category 2 (128-bit security).
    ///
    /// Dilithium-2: NIST 安全类别 2（128 位安全性）。
    ///
    /// ## Properties | 属性
    /// - **Security Level**: 128-bit (equivalent to AES-128)
    /// - **Public Key Size**: ~1,312 bytes
    /// - **Private Key Size**: ~2,528 bytes
    /// - **Signature Size**: ~2,420 bytes
    /// - **Performance**: Good balance of security and efficiency
    ///
    /// ## Use Cases | 使用场景
    /// Recommended for most applications requiring post-quantum signatures.
    /// 推荐用于大多数需要后量子签名的应用。
    L2,

    /// Dilithium-3: NIST security category 3 (192-bit security).
    ///
    /// Dilithium-3: NIST 安全类别 3（192 位安全性）。
    ///
    /// ## Properties | 属性
    /// - **Security Level**: 192-bit (equivalent to AES-192)
    /// - **Public Key Size**: ~1,952 bytes
    /// - **Private Key Size**: ~4,000 bytes
    /// - **Signature Size**: ~3,293 bytes
    /// - **Performance**: Moderate, higher security than Dilithium-2
    ///
    /// ## Use Cases | 使用场景
    /// For applications requiring higher security than 128-bit level.
    /// 用于需要高于 128 位级别安全性的应用。
    L3,

    /// Dilithium-5: NIST security category 5 (256-bit security).
    ///
    /// Dilithium-5: NIST 安全类别 5（256 位安全性）。
    ///
    /// ## Properties | 属性
    /// - **Security Level**: 256-bit (equivalent to AES-256)
    /// - **Public Key Size**: ~2,592 bytes
    /// - **Private Key Size**: ~4,864 bytes
    /// - **Signature Size**: ~4,595 bytes
    /// - **Performance**: Slower, but maximum post-quantum security
    ///
    /// ## Use Cases | 使用场景
    /// For the most sensitive applications requiring maximum security.
    /// 用于需要最大安全性的最敏感应用。
    L5,
}

/// Digital signature algorithm enumeration.
///
/// 数字签名算法枚举。
///
/// ## Algorithm Selection Guide | 算法选择指南
///
/// Choose based on your requirements:
///
/// 根据您的要求选择：
///
/// - **High Performance**: Ed25519
/// - **Standards Compliance**: ECDSA P-256
/// - **Post-Quantum Security**: Dilithium variants
/// - **Long-term Security**: Dilithium-5
/// - **Balanced Approach**: Dilithium-2
///
/// - **高性能**: Ed25519
/// - **标准合规性**: ECDSA P-256
/// - **后量子安全**: Dilithium 变体
/// - **长期安全**: Dilithium-5
/// - **平衡方法**: Dilithium-2
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, serde::Serialize, serde::Deserialize,
)]
pub enum SignatureAlgorithm {
    /// Dilithium post-quantum signature algorithm.
    ///
    /// Dilithium 后量子签名算法。
    ///
    /// Based on lattice cryptography, providing security against both classical
    /// and quantum computers. Standardized by NIST as FIPS 204.
    ///
    /// 基于格密码学，提供对经典和量子计算机的安全性。
    /// 由 NIST 标准化为 FIPS 204。
    Dilithium(DilithiumSecurityLevel),

    /// Ed25519 signature algorithm using Edwards curves.
    ///
    /// 使用 Edwards 曲线的 Ed25519 签名算法。
    ///
    /// High-performance signature algorithm with deterministic signatures.
    /// Based on Curve25519 and provides 128-bit security level.
    ///
    /// 具有确定性签名的高性能签名算法。
    /// 基于 Curve25519 并提供 128 位安全级别。
    Ed25519,

    /// ECDSA over NIST P-256 curve.
    ///
    /// 基于 NIST P-256 曲线的 ECDSA。
    ///
    /// Widely standardized and supported signature algorithm.
    /// Provides 128-bit security level with good performance.
    ///
    /// 广泛标准化和支持的签名算法。
    /// 提供 128 位安全级别和良好性能。
    EcdsaP256,
}

impl SignatureAlgorithm {
    /// Creates a new signature algorithm builder.
    ///
    /// 创建新的签名算法构建器。
    ///
    /// ## Returns | 返回值
    ///
    /// A builder that provides access to different signature algorithms.
    /// Use the builder methods to select the specific algorithm needed.
    ///
    /// 提供访问不同签名算法的构建器。
    /// 使用构建器方法选择所需的特定算法。
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::asymmetric::signature::SignatureAlgorithm;
    ///
    /// let ed25519 = SignatureAlgorithm::build().ed25519();
    /// let dilithium = SignatureAlgorithm::build().dilithium2();
    /// ```
    pub fn build() -> SignatureAlgorithmBuilder {
        SignatureAlgorithmBuilder
    }
}

/// Builder for constructing signature algorithm instances.
///
/// 用于构建签名算法实例的构建器。
///
/// ## Usage Pattern | 使用模式
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::asymmetric::signature::SignatureAlgorithm;
///
/// // Traditional algorithms
/// let ed25519 = SignatureAlgorithm::build().ed25519();
/// let ecdsa = SignatureAlgorithm::build().ecdsa_p256();
///
/// // Post-quantum algorithms
/// let dilithium2 = SignatureAlgorithm::build().dilithium2();
/// let dilithium3 = SignatureAlgorithm::build().dilithium3();
/// let dilithium5 = SignatureAlgorithm::build().dilithium5();
/// ```
///
/// ## Algorithm Selection Guidelines | 算法选择指南
///
/// Consider these factors when choosing:
/// - **Performance Requirements**: Ed25519 > ECDSA P-256 > Dilithium
/// - **Signature Size**: Ed25519 ≈ ECDSA P-256 << Dilithium
/// - **Quantum Resistance**: Only Dilithium provides quantum resistance
/// - **Standardization**: All algorithms are well-standardized
///
/// 选择时考虑这些因素：
/// - **性能要求**: Ed25519 > ECDSA P-256 > Dilithium
/// - **签名大小**: Ed25519 ≈ ECDSA P-256 << Dilithium
/// - **量子抗性**: 只有 Dilithium 提供量子抗性
/// - **标准化**: 所有算法都经过良好标准化
pub struct SignatureAlgorithmBuilder;

impl SignatureAlgorithmBuilder {
    /// Selects Dilithium-2 post-quantum signature algorithm.
    ///
    /// 选择 Dilithium-2 后量子签名算法。
    ///
    /// ## Properties | 属性
    /// - **Security Level**: 128-bit (NIST Category 2)
    /// - **Public Key**: ~1.3KB
    /// - **Private Key**: ~2.5KB
    /// - **Signature**: ~2.4KB
    /// - **Quantum Safe**: Yes
    ///
    /// ## Performance | 性能
    /// - **Key Generation**: ~0.1ms
    /// - **Signing**: ~0.2ms
    /// - **Verification**: ~0.1ms
    ///
    /// ## Use Cases | 使用场景
    /// Best choice for most post-quantum signature applications.
    /// 大多数后量子签名应用的最佳选择。
    pub fn dilithium2(self) -> SignatureAlgorithm {
        SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L2)
    }

    /// Selects Dilithium-3 post-quantum signature algorithm.
    ///
    /// 选择 Dilithium-3 后量子签名算法。
    ///
    /// ## Properties | 属性
    /// - **Security Level**: 192-bit (NIST Category 3)
    /// - **Public Key**: ~2KB
    /// - **Private Key**: ~4KB
    /// - **Signature**: ~3.3KB
    /// - **Quantum Safe**: Yes
    ///
    /// ## Use Cases | 使用场景
    /// For applications requiring higher security than 128-bit level.
    /// 用于需要高于 128 位级别安全性的应用。
    pub fn dilithium3(self) -> SignatureAlgorithm {
        SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L3)
    }

    /// Selects Dilithium-5 post-quantum signature algorithm.
    ///
    /// 选择 Dilithium-5 后量子签名算法。
    ///
    /// ## Properties | 属性
    /// - **Security Level**: 256-bit (NIST Category 5)
    /// - **Public Key**: ~2.6KB
    /// - **Private Key**: ~4.9KB
    /// - **Signature**: ~4.6KB
    /// - **Quantum Safe**: Yes
    ///
    /// ## Use Cases | 使用场景
    /// Maximum security for the most sensitive applications.
    /// 最敏感应用的最大安全性。
    pub fn dilithium5(self) -> SignatureAlgorithm {
        SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L5)
    }

    /// Selects Ed25519 signature algorithm.
    ///
    /// 选择 Ed25519 签名算法。
    ///
    /// ## Properties | 属性
    /// - **Security Level**: 128-bit
    /// - **Public Key**: 32 bytes
    /// - **Private Key**: 32 bytes
    /// - **Signature**: 64 bytes
    /// - **Quantum Safe**: No
    ///
    /// ## Advantages | 优势
    /// - **High Performance**: Fastest signature algorithm
    /// - **Deterministic**: Same message always produces same signature
    /// - **Small Keys**: Compact key and signature sizes
    /// - **No Hash Required**: Built-in message hashing
    ///
    /// - **高性能**: 最快的签名算法
    /// - **确定性**: 相同消息总是产生相同签名
    /// - **小密钥**: 紧凑的密钥和签名大小
    /// - **无需哈希**: 内置消息哈希
    ///
    /// ## Use Cases | 使用场景
    /// Ideal for high-performance applications not requiring quantum resistance.
    /// 适用于不需要量子抗性的高性能应用。
    pub fn ed25519(self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

    /// Selects ECDSA P-256 signature algorithm.
    ///
    /// 选择 ECDSA P-256 签名算法。
    ///
    /// ## Properties | 属性
    /// - **Security Level**: 128-bit
    /// - **Public Key**: 64 bytes (uncompressed)
    /// - **Private Key**: 32 bytes
    /// - **Signature**: ~64 bytes (variable)
    /// - **Quantum Safe**: No
    ///
    /// ## Advantages | 优势
    /// - **Wide Support**: Extensively supported across platforms
    /// - **Standards Compliance**: NIST FIPS 186-4, RFC 6090
    /// - **Interoperability**: Compatible with many systems
    /// - **Good Performance**: Efficient implementation
    ///
    /// - **广泛支持**: 跨平台广泛支持
    /// - **标准合规性**: NIST FIPS 186-4, RFC 6090
    /// - **互操作性**: 与许多系统兼容
    /// - **良好性能**: 高效实现
    ///
    /// ## Use Cases | 使用场景
    /// Best for applications requiring standards compliance and interoperability.
    /// 最适合需要标准合规性和互操作性的应用。
    pub fn ecdsa_p256(self) -> SignatureAlgorithm {
        SignatureAlgorithm::EcdsaP256
    }
}

use crate::wrappers::asymmetric::signature::SignatureAlgorithmWrapper;

impl SignatureAlgorithm {
    /// Converts the algorithm enum into a concrete wrapper implementation.
    ///
    /// 将算法枚举转换为具体的包装器实现。
    ///
    /// ## Purpose | 目的
    ///
    /// This method creates a wrapper that implements the signature algorithm trait,
    /// enabling actual cryptographic operations like key pair generation, message
    /// signing, and signature verification with type safety guarantees.
    ///
    /// 此方法创建一个实现签名算法 trait 的包装器，
    /// 启用实际的密码操作，如密钥对生成、消息签名和签名验证，并提供类型安全保证。
    ///
    /// ## Returns | 返回值
    ///
    /// A `SignatureAlgorithmWrapper` that can perform:
    /// - Key pair generation
    /// - Message signing
    /// - Signature verification
    /// - Algorithm introspection
    ///
    /// 可以执行以下操作的 `SignatureAlgorithmWrapper`：
    /// - 密钥对生成
    /// - 消息签名
    /// - 签名验证
    /// - 算法内省
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::asymmetric::signature::SignatureAlgorithm;
    ///
    /// let algorithm = SignatureAlgorithm::build().ed25519();
    /// let signer = algorithm.into_wrapper();
    ///
    /// // Generate key pair
    /// let keypair = signer.generate_keypair()?;
    /// let (public_key, private_key) = keypair.into_keypair();
    ///
    /// // Sign a message
    /// let message = b"Hello, World!";
    /// let signature = signer.sign(message, &private_key)?;
    ///
    /// // Verify the signature
    /// signer.verify(message, &public_key, &signature)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// ## Security Best Practices | 安全最佳实践
    ///
    /// When using the wrapper:
    /// 1. **Protect Private Keys**: Keep private keys secure and confidential
    /// 2. **Verify Signatures**: Always verify signatures before trusting data
    /// 3. **Use Fresh Keys**: Generate new keys for different purposes
    /// 4. **Hash Messages**: For large messages, hash before signing
    ///
    /// 使用包装器时：
    /// 1. **保护私钥**: 保持私钥安全和机密
    /// 2. **验证签名**: 在信任数据之前始终验证签名
    /// 3. **使用新密钥**: 为不同目的生成新密钥
    /// 4. **哈希消息**: 对于大消息，签名前先哈希
    ///
    /// ## Algorithm-Specific Notes | 算法特定注意事项
    ///
    /// - **Ed25519**: Deterministic signatures, no additional randomness needed
    /// - **ECDSA P-256**: Requires high-quality randomness for each signature
    /// - **Dilithium**: Post-quantum secure, larger keys and signatures
    ///
    /// - **Ed25519**: 确定性签名，不需要额外的随机性
    /// - **ECDSA P-256**: 每个签名都需要高质量的随机性
    /// - **Dilithium**: 后量子安全，更大的密钥和签名
    pub fn into_wrapper(self) -> SignatureAlgorithmWrapper {
        use crate::wrappers::asymmetric::signature::{
            Dilithium2Wrapper, Dilithium3Wrapper, Dilithium5Wrapper, EcdsaP256Wrapper,
            Ed25519Wrapper,
        };
        match self {
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L2) => {
                SignatureAlgorithmWrapper::new(Box::new(Dilithium2Wrapper::default()))
            }
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L3) => {
                SignatureAlgorithmWrapper::new(Box::new(Dilithium3Wrapper::default()))
            }
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L5) => {
                SignatureAlgorithmWrapper::new(Box::new(Dilithium5Wrapper::default()))
            }
            SignatureAlgorithm::Ed25519 => {
                SignatureAlgorithmWrapper::new(Box::new(Ed25519Wrapper::default()))
            }
            SignatureAlgorithm::EcdsaP256 => {
                SignatureAlgorithmWrapper::new(Box::new(EcdsaP256Wrapper::default()))
            }
        }
    }
}
