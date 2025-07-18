//! Key Derivation Functions (KDF) for secure key generation and management.
//!
//! 用于安全密钥生成和管理的密钥派生函数 (KDF)。
//!
//! ## Overview | 概述
//!
//! Key Derivation Functions are cryptographic algorithms that derive one or more
//! secret keys from a secret value such as a master key, password, or shared secret.
//! They are essential for secure key management and cryptographic protocol design.
//!
//! 密钥派生函数是从主密钥、密码或共享密钥等秘密值派生一个或多个密钥的密码算法。
//! 它们对于安全密钥管理和密码协议设计至关重要。
//!
//! ## KDF Categories | KDF 分类
//!
//! ### Key-Based KDF | 基于密钥的 KDF
//! - **HKDF**: HMAC-based Key Derivation Function (RFC 5869)
//!   - Suitable for deriving keys from high-entropy sources
//!   - Fast and efficient
//!   - Supports salt and context information
//!
//! ### Password-Based KDF | 基于密码的 KDF
//! - **PBKDF2**: Password-Based Key Derivation Function 2 (RFC 2898)
//!   - Widely supported and standardized
//!   - Configurable iteration count
//!   - Suitable for password-based encryption
//! - **Argon2**: Memory-hard password hashing function
//!   - Resistant to GPU and ASIC attacks
//!   - Configurable memory, time, and parallelism
//!   - Winner of Password Hashing Competition
//!
//! ## Security Considerations | 安全考虑
//!
//! ### Key-Based KDF | 基于密钥的 KDF
//! - Input key material should have sufficient entropy
//! - Use unique salt values when possible
//! - Context information helps prevent key reuse
//!
//! ### Password-Based KDF | 基于密码的 KDF
//! - Use high iteration counts to slow down attacks
//! - Always use random salts to prevent rainbow table attacks
//! - Consider memory-hard functions (Argon2) for better security
//!
//! ## Usage Guidelines | 使用指南
//!
//! - **High-entropy sources**: Use key-based KDF (HKDF)
//! - **Password derivation**: Use password-based KDF (PBKDF2/Argon2)
//! - **Performance critical**: HKDF or PBKDF2 with moderate iterations
//! - **Maximum security**: Argon2 with high memory and time costs
//!
//! - **高熵源**: 使用基于密钥的 KDF (HKDF)
//! - **密码派生**: 使用基于密码的 KDF (PBKDF2/Argon2)
//! - **性能关键**: HKDF 或适度迭代的 PBKDF2
//! - **最大安全性**: 高内存和时间成本的 Argon2

// Key-based derivation functions | 基于密钥的派生函数
pub mod key;
// Password-based derivation functions | 基于密码的派生函数
pub mod passwd;

use self::{key::KdfKeyAlgorithm, passwd::KdfPasswordAlgorithm};

/// Key Derivation Function algorithm enumeration.
///
/// 密钥派生函数算法枚举。
///
/// ## Algorithm Selection | 算法选择
///
/// This enum provides access to two main categories of KDF algorithms:
///
/// 此枚举提供对两个主要 KDF 算法类别的访问：
///
/// - **Key-based**: For deriving keys from existing high-entropy key material
/// - **Password-based**: For deriving keys from user passwords or low-entropy sources
///
/// - **基于密钥**: 用于从现有高熵密钥材料派生密钥
/// - **基于密码**: 用于从用户密码或低熵源派生密钥
///
/// ## Usage Examples | 使用示例
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::kdf::KdfAlgorithm;
///
/// // Key-based derivation (high entropy input)
/// let hkdf = KdfAlgorithm::build().key().hkdf_sha256();
///
/// // Password-based derivation (low entropy input)
/// let pbkdf2 = KdfAlgorithm::build().passwd().pbkdf2_sha256_with_params(10000);
/// let argon2 = KdfAlgorithm::build().passwd().argon2_with_params(65536, 3, 4);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KdfAlgorithm {
    /// Key-based derivation functions for high-entropy inputs.
    ///
    /// 用于高熵输入的基于密钥的派生函数。
    ///
    /// Suitable when the input key material already has sufficient entropy,
    /// such as cryptographic keys, shared secrets, or random values.
    ///
    /// 适用于输入密钥材料已具有足够熵的情况，
    /// 如密码密钥、共享密钥或随机值。
    Key(KdfKeyAlgorithm),

    /// Password-based derivation functions for low-entropy inputs.
    ///
    /// 用于低熵输入的基于密码的派生函数。
    ///
    /// Designed to handle user passwords and other low-entropy sources,
    /// with built-in protection against brute-force attacks.
    ///
    /// 设计用于处理用户密码和其他低熵源，
    /// 内置对暴力攻击的保护。
    Password(KdfPasswordAlgorithm),
}

impl KdfAlgorithm {
    /// Creates a new KDF algorithm builder.
    ///
    /// 创建新的 KDF 算法构建器。
    ///
    /// ## Returns | 返回值
    ///
    /// A builder that provides access to both key-based and password-based
    /// derivation functions. Use the builder methods to select the appropriate
    /// category for your use case.
    ///
    /// 提供访问基于密钥和基于密码的派生函数的构建器。
    /// 使用构建器方法为您的用例选择适当的类别。
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::kdf::KdfAlgorithm;
    ///
    /// // Access key-based KDF algorithms
    /// let key_builder = KdfAlgorithm::build().key();
    ///
    /// // Access password-based KDF algorithms
    /// let passwd_builder = KdfAlgorithm::build().passwd();
    /// ```
    pub fn build() -> KdfAlgorithmBuilder {
        KdfAlgorithmBuilder
    }
}

/// Builder for constructing KDF algorithm instances.
///
/// 用于构建 KDF 算法实例的构建器。
///
/// ## Design Pattern | 设计模式
///
/// This builder separates key-based and password-based derivation functions,
/// ensuring that the appropriate algorithm is chosen for the input entropy level.
///
/// 此构建器分离基于密钥和基于密码的派生函数，
/// 确保为输入熵级别选择适当的算法。
///
/// ## Security Guidance | 安全指导
///
/// - Use `.key()` for high-entropy inputs (≥128 bits of entropy)
/// - Use `.passwd()` for low-entropy inputs (user passwords, PINs)
///
/// - 对高熵输入使用 `.key()`（≥128 位熵）
/// - 对低熵输入使用 `.passwd()`（用户密码、PIN）
pub struct KdfAlgorithmBuilder;

impl KdfAlgorithmBuilder {
    /// Creates a key-based KDF algorithm builder.
    ///
    /// 创建基于密钥的 KDF 算法构建器。
    ///
    /// ## Use Cases | 使用场景
    ///
    /// - Deriving multiple keys from a master key
    /// - Key expansion in cryptographic protocols
    /// - Deriving keys from shared secrets (ECDH, etc.)
    /// - Creating domain-separated keys
    ///
    /// - 从主密钥派生多个密钥
    /// - 密码协议中的密钥扩展
    /// - 从共享密钥派生密钥（ECDH 等）
    /// - 创建域分离的密钥
    ///
    /// ## Available Algorithms | 可用算法
    ///
    /// - **HKDF-SHA256**: Fast, widely supported
    /// - **HKDF-SHA384**: Higher security margin
    /// - **HKDF-SHA512**: Maximum security
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::kdf::KdfAlgorithm;
    ///
    /// let hkdf = KdfAlgorithm::build().key().hkdf_sha256();
    /// ```
    pub fn key(self) -> key::KdfKeyAlgorithmBuilder {
        key::KdfKeyAlgorithm::build()
    }

    /// Creates a password-based KDF algorithm builder.
    ///
    /// 创建基于密码的 KDF 算法构建器。
    ///
    /// ## Use Cases | 使用场景
    ///
    /// - Deriving encryption keys from user passwords
    /// - Password-based authentication
    /// - Secure password storage
    /// - Key derivation for encrypted storage
    ///
    /// - 从用户密码派生加密密钥
    /// - 基于密码的认证
    /// - 安全密码存储
    /// - 加密存储的密钥派生
    ///
    /// ## Available Algorithms | 可用算法
    ///
    /// - **PBKDF2**: Widely supported, configurable iterations
    /// - **Argon2**: Memory-hard, resistant to specialized attacks
    ///
    /// ## Security Note | 安全注意
    ///
    /// Always use sufficient iteration counts and random salts to protect
    /// against brute-force and rainbow table attacks.
    ///
    /// 始终使用足够的迭代次数和随机盐来防止暴力攻击和彩虹表攻击。
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::kdf::KdfAlgorithm;
    ///
    /// // PBKDF2 with 100,000 iterations
    /// let pbkdf2 = KdfAlgorithm::build().passwd().pbkdf2_sha256(100000);
    ///
    /// // Argon2 with memory cost, time cost, and parallelism
    /// let argon2 = KdfAlgorithm::build().passwd().argon2(65536, 3, 4);
    /// ```
    pub fn passwd(self) -> passwd::KdfPasswordAlgorithmBuilder {
        passwd::KdfPasswordAlgorithm::build()
    }
}
