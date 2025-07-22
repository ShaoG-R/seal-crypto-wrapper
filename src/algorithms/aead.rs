//! Aead encryption algorithms with Authenticated Encryption with Associated Data (AEAD).
//!
//! 带关联数据认证加密 (AEAD) 的对称加密算法。
//!
//! ## Overview | 概述
//!
//! This module provides aead encryption algorithms that combine confidentiality
//! and authenticity in a single operation. All algorithms implement AEAD (Authenticated
//! Encryption with Associated Data), providing both encryption and authentication.
//!
//! 此模块提供在单个操作中结合机密性和真实性的对称加密算法。
//! 所有算法都实现 AEAD（带关联数据的认证加密），提供加密和认证。
//!
//! ## Supported Algorithms | 支持的算法
//!
//! ### AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)
//! - **AES-128-GCM**: 128-bit key, high performance, widely supported
//! - **AES-256-GCM**: 256-bit key, maximum security, future-proof
//!
//! ### ChaCha20-Poly1305
//! - **ChaCha20-Poly1305**: 256-bit key, software-optimized, constant-time
//! - **XChaCha20-Poly1305**: Extended nonce variant, 192-bit nonce
//!
//! ## Performance Comparison | 性能对比
//!
//! | Algorithm | Key Size | Nonce Size | Performance | Hardware Support |
//! |-----------|----------|------------|-------------|------------------|
//! | AES-128-GCM | 128-bit | 96-bit | Very High* | AES-NI |
//! | AES-256-GCM | 256-bit | 96-bit | Very High* | AES-NI |
//! | ChaCha20-Poly1305 | 256-bit | 96-bit | High | Software |
//! | XChaCha20-Poly1305 | 256-bit | 192-bit | High | Software |
//!
//! *With hardware acceleration
//!
//! ## Security Considerations | 安全考虑
//!
//! - **Nonce Reuse**: Never reuse nonces with the same key
//! - **Key Management**: Use cryptographically secure random keys
//! - **Associated Data**: Use for context binding when available
//! - **Implementation**: All algorithms are constant-time and side-channel resistant
//!
//! - **Nonce 重用**: 永远不要在同一密钥下重用 nonce
//! - **密钥管理**: 使用密码学安全的随机密钥
//! - **关联数据**: 可用时用于上下文绑定
//! - **实现**: 所有算法都是常数时间且抗侧信道的

use bincode::{Decode, Encode};

/// Aead encryption algorithm enumeration.
///
/// 对称加密算法枚举。
///
/// ## Algorithm Selection Guide | 算法选择指南
///
/// Choose based on your requirements:
///
/// 根据您的要求选择：
///
/// - **High Performance + Hardware**: AES-128-GCM or AES-256-GCM
/// - **Software Implementation**: ChaCha20-Poly1305
/// - **Large Nonces**: XChaCha20-Poly1305
/// - **Maximum Security**: AES-256-GCM or ChaCha20-Poly1305
///
/// - **高性能 + 硬件**: AES-128-GCM 或 AES-256-GCM
/// - **软件实现**: ChaCha20-Poly1305
/// - **大 Nonce**: XChaCha20-Poly1305
/// - **最大安全性**: AES-256-GCM 或 ChaCha20-Poly1305
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, serde::Serialize, serde::Deserialize,
)]
pub enum AeadAlgorithm {
    /// AES in Galois/Counter Mode with configurable key size.
    ///
    /// 具有可配置密钥大小的 Galois/Counter 模式 AES。
    ///
    /// Provides excellent performance on systems with AES hardware acceleration.
    /// Industry standard with extensive analysis and widespread adoption.
    ///
    /// 在具有 AES 硬件加速的系统上提供出色的性能。
    /// 行业标准，经过广泛分析和广泛采用。
    AesGcm(AesKeySize),

    /// ChaCha20 stream cipher with Poly1305 authenticator.
    ///
    /// ChaCha20 流密码与 Poly1305 认证器。
    ///
    /// Designed for high performance in software implementations.
    /// Provides excellent security with constant-time operations.
    ///
    /// 专为软件实现中的高性能而设计。
    /// 通过常数时间操作提供出色的安全性。
    ChaCha20Poly1305,

    /// Extended-nonce ChaCha20-Poly1305 variant.
    ///
    /// 扩展 nonce 的 ChaCha20-Poly1305 变体。
    ///
    /// Uses 192-bit nonces, reducing the risk of nonce collisions.
    /// Ideal for applications generating many encrypted messages.
    ///
    /// 使用 192 位 nonce，降低 nonce 碰撞的风险。
    /// 适用于生成许多加密消息的应用。
    XChaCha20Poly1305,
}

/// AES key size variants.
///
/// AES 密钥大小变体。
///
/// ## Security Levels | 安全级别
///
/// Both variants provide strong security, with AES-256 offering higher
/// theoretical security margin for long-term protection.
///
/// 两种变体都提供强大的安全性，AES-256 为长期保护提供更高的理论安全边际。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, serde::Serialize, serde::Deserialize,
)]
pub enum AesKeySize {
    /// 128-bit AES key (128-bit security level).
    ///
    /// 128 位 AES 密钥（128 位安全级别）。
    ///
    /// Provides excellent security for most applications with optimal performance.
    /// Recommended for general-purpose use.
    ///
    /// 为大多数应用提供出色的安全性和最佳性能。
    /// 推荐用于通用目的。
    K128,

    /// 256-bit AES key (256-bit security level).
    ///
    /// 256 位 AES 密钥（256 位安全级别）。
    ///
    /// Provides maximum security for high-value or long-term protection scenarios.
    /// Future-proof against advances in cryptanalysis.
    ///
    /// 为高价值或长期保护场景提供最大安全性。
    /// 防范密码分析技术的进步。
    K256,
}

impl AeadAlgorithm {
    /// Creates a new aead algorithm builder.
    ///
    /// 创建新的对称算法构建器。
    ///
    /// # Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::aead::AeadAlgorithm;
    ///
    /// let algorithm = AeadAlgorithm::build().aes256_gcm();
    /// ```
    pub fn build() -> AeadAlgorithmBuilder {
        AeadAlgorithmBuilder
    }
}

/// Builder for constructing aead algorithm instances.
///
/// 用于构建对称算法实例的构建器。
///
/// ## Usage Pattern | 使用模式
///
/// The builder provides a fluent interface for algorithm selection:
///
/// 构建器为算法选择提供流畅的接口：
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::aead::AeadAlgorithm;
///
/// // High performance with hardware acceleration
/// let aes = AeadAlgorithm::build().aes256_gcm();
///
/// // Software-optimized
/// let chacha = AeadAlgorithm::build().chacha20_poly1305();
///
/// // Extended nonce support
/// let xchacha = AeadAlgorithm::build().xchacha20_poly1305();
/// ```
pub struct AeadAlgorithmBuilder;

impl AeadAlgorithmBuilder {
    /// Selects AES-128-GCM algorithm.
    ///
    /// 选择 AES-128-GCM 算法。
    ///
    /// ## Properties | 属性
    /// - Key size: 128 bits
    /// - Nonce size: 96 bits (12 bytes)
    /// - Tag size: 128 bits (16 bytes)
    /// - Security level: 128-bit
    ///
    /// ## Performance | 性能
    /// Excellent with AES-NI hardware acceleration.
    /// 在 AES-NI 硬件加速下表现出色。
    pub fn aes128_gcm(self) -> AeadAlgorithm {
        AeadAlgorithm::AesGcm(AesKeySize::K128)
    }

    /// Selects AES-256-GCM algorithm.
    ///
    /// 选择 AES-256-GCM 算法。
    ///
    /// ## Properties | 属性
    /// - Key size: 256 bits
    /// - Nonce size: 96 bits (12 bytes)
    /// - Tag size: 128 bits (16 bytes)
    /// - Security level: 256-bit
    ///
    /// ## Use Cases | 使用场景
    /// Recommended for high-security applications and long-term data protection.
    /// 推荐用于高安全性应用和长期数据保护。
    pub fn aes256_gcm(self) -> AeadAlgorithm {
        AeadAlgorithm::AesGcm(AesKeySize::K256)
    }

    /// Selects ChaCha20-Poly1305 algorithm.
    ///
    /// 选择 ChaCha20-Poly1305 算法。
    ///
    /// ## Properties | 属性
    /// - Key size: 256 bits
    /// - Nonce size: 96 bits (12 bytes)
    /// - Tag size: 128 bits (16 bytes)
    /// - Security level: 256-bit
    ///
    /// ## Advantages | 优势
    /// - Constant-time implementation
    /// - No timing side-channels
    /// - Excellent software performance
    /// - 常数时间实现
    /// - 无时序侧信道
    /// - 出色的软件性能
    pub fn chacha20_poly1305(self) -> AeadAlgorithm {
        AeadAlgorithm::ChaCha20Poly1305
    }

    /// Selects XChaCha20-Poly1305 algorithm.
    ///
    /// 选择 XChaCha20-Poly1305 算法。
    ///
    /// ## Properties | 属性
    /// - Key size: 256 bits
    /// - Nonce size: 192 bits (24 bytes)
    /// - Tag size: 128 bits (16 bytes)
    /// - Security level: 256-bit
    ///
    /// ## Key Feature | 关键特性
    /// Extended 192-bit nonce eliminates nonce collision concerns.
    /// 扩展的 192 位 nonce 消除了 nonce 碰撞的担忧。
    pub fn xchacha20_poly1305(self) -> AeadAlgorithm {
        AeadAlgorithm::XChaCha20Poly1305
    }
}

use crate::wrappers::aead::AeadAlgorithmWrapper;

impl AeadAlgorithm {
    /// Converts the algorithm enum into a concrete wrapper implementation.
    ///
    /// 将算法枚举转换为具体的包装器实现。
    ///
    /// ## Purpose | 目的
    ///
    /// This method bridges the gap between algorithm selection and actual cryptographic
    /// operations. It returns a wrapper that implements the aead algorithm trait,
    /// enabling type-safe encryption and decryption operations.
    ///
    /// 此方法在算法选择和实际密码操作之间架起桥梁。
    /// 它返回一个实现对称算法 trait 的包装器，启用类型安全的加密和解密操作。
    ///
    /// ## Returns | 返回值
    ///
    /// A `AeadAlgorithmWrapper` that can perform:
    /// - Key generation
    /// - Encryption with authentication
    /// - Decryption with verification
    /// - Algorithm introspection
    ///
    /// 可以执行以下操作的 `AeadAlgorithmWrapper`：
    /// - 密钥生成
    /// - 带认证的加密
    /// - 带验证的解密
    /// - 算法内省
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::aead::AeadAlgorithm;
    ///
    /// let algorithm = AeadAlgorithm::build().aes256_gcm();
    /// let cipher = algorithm.into_wrapper();
    ///
    /// // Now you can use the cipher for encryption/decryption
    /// let key = cipher.generate_typed_key()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn into_wrapper(self) -> AeadAlgorithmWrapper {
        use crate::wrappers::aead::{
            Aes128GcmWrapper, Aes256GcmWrapper, ChaCha20Poly1305Wrapper, XChaCha20Poly1305Wrapper,
        };
        match self {
            AeadAlgorithm::AesGcm(AesKeySize::K128) => {
                AeadAlgorithmWrapper::new(Box::new(Aes128GcmWrapper::default()))
            }
            AeadAlgorithm::AesGcm(AesKeySize::K256) => {
                AeadAlgorithmWrapper::new(Box::new(Aes256GcmWrapper::default()))
            }
            AeadAlgorithm::ChaCha20Poly1305 => {
                AeadAlgorithmWrapper::new(Box::new(ChaCha20Poly1305Wrapper::default()))
            }
            AeadAlgorithm::XChaCha20Poly1305 => {
                AeadAlgorithmWrapper::new(Box::new(XChaCha20Poly1305Wrapper::default()))
            }
        }
    }
}
