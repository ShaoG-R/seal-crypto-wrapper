//! Key agreement algorithms for establishing shared secrets.
//!
//! 用于建立共享密钥的密钥协商算法。
//!
//! ## Overview | 概述
//!
//! Key agreement algorithms allow two or more parties to establish a shared secret
//! over an insecure communication channel without prior shared information. The
//! shared secret can then be used for symmetric encryption or other cryptographic
//! operations requiring a common key.
//!
//! 密钥协商算法允许两方或多方在没有事先共享信息的情况下，
//! 通过不安全的通信通道建立共享密钥。然后可以将共享密钥用于对称加密
//! 或其他需要公共密钥的密码操作。
//!
//! ## Supported Algorithms | 支持的算法
//!
//! ### ECDH P-256 (Elliptic Curve Diffie-Hellman)
//! - **Curve**: NIST P-256 (secp256r1)
//! - **Security Level**: 128-bit
//! - **Key Size**: 32 bytes (256 bits)
//! - **Performance**: High
//! - **Standardization**: NIST FIPS 186-4, RFC 6090
//!
//! ## Security Properties | 安全属性
//!
//! - **Computational Diffie-Hellman (CDH)**: Based on the difficulty of computing discrete logarithms
//! - **Forward Secrecy**: When used with ephemeral keys
//! - **Perfect Forward Secrecy**: When ephemeral keys are properly deleted
//! - **No Authentication**: Key agreement alone doesn't provide authentication
//!
//! - **计算 Diffie-Hellman (CDH)**: 基于计算离散对数的困难性
//! - **前向保密**: 当与临时密钥一起使用时
//! - **完美前向保密**: 当临时密钥被正确删除时
//! - **无认证**: 密钥协商本身不提供认证
//!
//! ## Usage Guidelines | 使用指南
//!
//! - **Authentication**: Combine with digital signatures or certificates for authentication
//! - **Ephemeral Keys**: Use ephemeral keys for forward secrecy
//! - **Key Derivation**: Use proper KDF to derive actual encryption keys from shared secret
//! - **Validation**: Validate public keys to prevent invalid curve attacks
//!
//! - **认证**: 结合数字签名或证书进行认证
//! - **临时密钥**: 使用临时密钥实现前向保密
//! - **密钥派生**: 使用适当的 KDF 从共享密钥派生实际的加密密钥
//! - **验证**: 验证公钥以防止无效曲线攻击

use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Key agreement algorithm enumeration.
///
/// 密钥协商算法枚举。
///
/// ## Algorithm Selection | 算法选择
///
/// Currently supports ECDH P-256, which provides:
/// - High performance on modern hardware
/// - Wide compatibility and standardization
/// - 128-bit security level
/// - Efficient implementation
///
/// 目前支持 ECDH P-256，它提供：
/// - 在现代硬件上的高性能
/// - 广泛的兼容性和标准化
/// - 128 位安全级别
/// - 高效的实现
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, Serialize, Deserialize)]
pub enum KeyAgreementAlgorithm {
    /// Elliptic Curve Diffie-Hellman over NIST P-256 curve.
    ///
    /// 基于 NIST P-256 曲线的椭圆曲线 Diffie-Hellman。
    ///
    /// ## Properties | 属性
    /// - **Curve**: NIST P-256 (secp256r1)
    /// - **Field Size**: 256 bits
    /// - **Security Level**: 128-bit
    /// - **Key Size**: 32 bytes
    /// - **Shared Secret Size**: 32 bytes
    ///
    /// ## Use Cases | 使用场景
    /// - TLS/SSL key exchange
    /// - Secure messaging protocols
    /// - VPN key establishment
    /// - IoT device pairing
    ///
    /// - TLS/SSL 密钥交换
    /// - 安全消息协议
    /// - VPN 密钥建立
    /// - IoT 设备配对
    EcdhP256,
}

impl KeyAgreementAlgorithm {
    /// Creates a new key agreement algorithm builder.
    ///
    /// 创建新的密钥协商算法构建器。
    ///
    /// ## Returns | 返回值
    ///
    /// A builder that provides access to different key agreement algorithms.
    /// Use the builder methods to select the specific algorithm needed.
    ///
    /// 提供访问不同密钥协商算法的构建器。
    /// 使用构建器方法选择所需的特定算法。
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;
    ///
    /// let ecdh = KeyAgreementAlgorithm::build().ecdh_p256();
    /// ```
    pub fn build() -> KeyAgreementAlgorithmBuilder {
        KeyAgreementAlgorithmBuilder
    }
}

/// Builder for constructing key agreement algorithm instances.
///
/// 用于构建密钥协商算法实例的构建器。
///
/// ## Usage Pattern | 使用模式
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;
///
/// // Select ECDH P-256 algorithm
/// let algorithm = KeyAgreementAlgorithm::build().ecdh_p256();
/// ```
///
/// ## Security Considerations | 安全考虑
///
/// When selecting a key agreement algorithm, consider:
/// - Required security level
/// - Performance requirements
/// - Compatibility with other systems
/// - Forward secrecy requirements
///
/// 选择密钥协商算法时，考虑：
/// - 所需的安全级别
/// - 性能要求
/// - 与其他系统的兼容性
/// - 前向保密要求
pub struct KeyAgreementAlgorithmBuilder;

impl KeyAgreementAlgorithmBuilder {
    /// Selects ECDH P-256 key agreement algorithm.
    ///
    /// 选择 ECDH P-256 密钥协商算法。
    ///
    /// ## Algorithm Details | 算法详情
    ///
    /// ECDH (Elliptic Curve Diffie-Hellman) over the NIST P-256 curve provides:
    /// - 128-bit security level
    /// - Efficient computation
    /// - Wide industry support
    /// - FIPS 140-2 compliance
    ///
    /// 基于 NIST P-256 曲线的 ECDH（椭圆曲线 Diffie-Hellman）提供：
    /// - 128 位安全级别
    /// - 高效计算
    /// - 广泛的行业支持
    /// - FIPS 140-2 合规性
    ///
    /// ## Performance | 性能
    ///
    /// - **Key Generation**: Very fast (~0.1ms)
    /// - **Key Agreement**: Fast (~0.2ms)
    /// - **Memory Usage**: Low (64 bytes per key pair)
    /// - **Hardware Support**: Available on many platforms
    ///
    /// ## Use Cases | 使用场景
    ///
    /// Ideal for applications requiring:
    /// - High performance key exchange
    /// - Standards compliance
    /// - Interoperability
    /// - Moderate security requirements
    ///
    /// 适用于需要以下功能的应用：
    /// - 高性能密钥交换
    /// - 标准合规性
    /// - 互操作性
    /// - 中等安全要求
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;
    ///
    /// let algorithm = KeyAgreementAlgorithm::build().ecdh_p256();
    /// let ka = algorithm.into_key_agreement_wrapper();
    ///
    /// // Generate key pairs for Alice and Bob
    /// let alice_keypair = ka.generate_keypair()?;
    /// let bob_keypair = ka.generate_keypair()?;
    ///
    /// // Derive shared secrets
    /// let (alice_public, alice_private) = alice_keypair.into_keypair();
    /// let (bob_public, bob_private) = bob_keypair.into_keypair();
    ///
    /// let alice_shared = ka.agree(&alice_private, &bob_public)?;
    /// let bob_shared = ka.agree(&bob_private, &alice_public)?;
    /// assert_eq!(alice_shared, bob_shared);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn ecdh_p256(self) -> KeyAgreementAlgorithm {
        KeyAgreementAlgorithm::EcdhP256
    }
}

use crate::wrappers::asymmetric::key_agreement::KeyAgreementAlgorithmWrapper;

impl KeyAgreementAlgorithm {
    /// Converts the algorithm enum into a concrete wrapper implementation.
    ///
    /// 将算法枚举转换为具体的包装器实现。
    ///
    /// ## Purpose | 目的
    ///
    /// This method creates a wrapper that implements the key agreement algorithm trait,
    /// enabling actual cryptographic operations like key pair generation and shared
    /// secret derivation with type safety guarantees.
    ///
    /// 此方法创建一个实现密钥协商算法 trait 的包装器，
    /// 启用实际的密码操作，如密钥对生成和共享密钥派生，并提供类型安全保证。
    ///
    /// ## Returns | 返回值
    ///
    /// A `KeyAgreementAlgorithmWrapper` that can perform:
    /// - Key pair generation
    /// - Shared secret derivation (key agreement)
    /// - Public key validation
    /// - Algorithm introspection
    ///
    /// 可以执行以下操作的 `KeyAgreementAlgorithmWrapper`：
    /// - 密钥对生成
    /// - 共享密钥派生（密钥协商）
    /// - 公钥验证
    /// - 算法内省
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;
    ///
    /// let algorithm = KeyAgreementAlgorithm::build().ecdh_p256();
    /// let ka = algorithm.into_key_agreement_wrapper();
    ///
    /// // Generate key pairs for two parties
    /// let alice_keypair = ka.generate_keypair()?;
    /// let bob_keypair = ka.generate_keypair()?;
    ///
    /// // Extract keys
    /// let (alice_public, alice_private) = alice_keypair.into_keypair();
    /// let (bob_public, bob_private) = bob_keypair.into_keypair();
    ///
    /// // Both parties derive the same shared secret
    /// let alice_shared = ka.agree(&alice_private, &bob_public)?;
    /// let bob_shared = ka.agree(&bob_private, &alice_public)?;
    ///
    /// // Verify they match
    /// assert_eq!(alice_shared, bob_shared);
    ///
    /// // Use shared secret for key derivation
    /// // (In practice, use a proper KDF like HKDF)
    /// let encryption_key = &alice_shared[..32]; // First 32 bytes
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// ## Security Best Practices | 安全最佳实践
    ///
    /// When using the wrapper:
    /// 1. **Validate Public Keys**: Always validate received public keys
    /// 2. **Use Ephemeral Keys**: Generate new keys for each session
    /// 3. **Proper Key Derivation**: Use HKDF or similar to derive actual keys
    /// 4. **Authentication**: Combine with signatures for authenticated key exchange
    ///
    /// 使用包装器时：
    /// 1. **验证公钥**: 始终验证接收到的公钥
    /// 2. **使用临时密钥**: 为每个会话生成新密钥
    /// 3. **适当的密钥派生**: 使用 HKDF 或类似方法派生实际密钥
    /// 4. **认证**: 结合签名进行认证密钥交换
    pub fn into_key_agreement_wrapper(self) -> KeyAgreementAlgorithmWrapper {
        use crate::wrappers::asymmetric::key_agreement::EcdhP256Wrapper;
        match self {
            KeyAgreementAlgorithm::EcdhP256 => {
                KeyAgreementAlgorithmWrapper::new(Box::new(EcdhP256Wrapper::default()))
            }
        }
    }
}
