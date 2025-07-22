//! Key-based Key Derivation Function (KDF) algorithm wrappers for high-entropy inputs.
//!
//! 用于高熵输入的基于密钥的密钥派生函数 (KDF) 算法包装器。
//!
//! ## Overview | 概述
//!
//! This module provides concrete implementations of key-based KDF algorithms
//! that are designed to work with high-entropy input key material. These
//! algorithms efficiently expand or derive multiple keys from a single
//! master key or shared secret.
//!
//! 此模块提供基于密钥的 KDF 算法的具体实现，
//! 设计用于处理高熵输入密钥材料。这些算法有效地从单个主密钥或共享密钥
//! 扩展或派生多个密钥。
//!
//! ## Supported Algorithms | 支持的算法
//!
//! ### HKDF (HMAC-based Key Derivation Function)
//! - **HKDF-SHA256**: Fast, widely supported, 128-bit security
//! - **HKDF-SHA384**: Higher security margin, 192-bit security
//! - **HKDF-SHA512**: Maximum security, 256-bit security
//!
//! ## HKDF Process | HKDF 过程
//!
//! HKDF operates in two phases:
//! 1. **Extract**: `PRK = HKDF-Extract(salt, IKM)`
//! 2. **Expand**: `OKM = HKDF-Expand(PRK, info, L)`
//!
//! HKDF 分两个阶段运行：
//! 1. **提取**: `PRK = HKDF-Extract(salt, IKM)`
//! 2. **扩展**: `OKM = HKDF-Expand(PRK, info, L)`
//!
//! ## Use Cases | 使用场景
//!
//! - Key expansion in cryptographic protocols
//! - Deriving multiple keys from shared secrets
//! - Domain separation for different key purposes
//! - Converting high-entropy sources to usable keys
//!
//! - 密码协议中的密钥扩展
//! - 从共享密钥派生多个密钥
//! - 不同密钥用途的域分离
//! - 将高熵源转换为可用密钥
//!
//! ## Security Properties | 安全属性
//!
//! - **Pseudorandomness**: Output indistinguishable from random
//! - **Key Separation**: Different contexts produce independent keys
//! - **Forward Security**: Compromise of derived keys doesn't affect others
//! - **Efficiency**: Fast computation suitable for real-time use
//!
//! - **伪随机性**: 输出与随机数据无法区分
//! - **密钥分离**: 不同上下文产生独立密钥
//! - **前向安全**: 派生密钥的泄露不影响其他密钥
//! - **效率**: 适用于实时使用的快速计算

use crate::algorithms::HashAlgorithmEnum;
use crate::algorithms::kdf::key::KdfKeyAlgorithm;
use crate::define_wrapper;
use crate::error::{Error, Result};
use crate::traits::KdfKeyAlgorithmTrait;
use seal_crypto::prelude::KeyBasedDerivation;
use seal_crypto::schemes::kdf::hkdf::{HkdfSha256, HkdfSha384, HkdfSha512};
use seal_crypto::zeroize::Zeroizing;
use std::ops::Deref;

/// Macro for implementing key-based KDF algorithm wrappers.
///
/// 用于实现基于密钥的 KDF 算法包装器的宏。
///
/// This macro generates a complete wrapper implementation for a key-based KDF algorithm,
/// including all required trait methods, input validation, and error handling.
/// It ensures secure key derivation with proper memory management.
///
/// 此宏为基于密钥的 KDF 算法生成完整的包装器实现，
/// 包括所有必需的 trait 方法、输入验证和错误处理。
/// 它确保通过适当的内存管理进行安全密钥派生。
///
/// ## Parameters | 参数
///
/// - `$wrapper`: The name of the wrapper struct to generate
/// - `$algo`: The underlying algorithm type from seal-crypto
/// - `$algo_enum`: The corresponding algorithm enum variant
///
/// - `$wrapper`: 要生成的包装器结构体名称
/// - `$algo`: 来自 seal-crypto 的底层算法类型
/// - `$algo_enum`: 对应的算法枚举变体
///
/// ## Generated Methods | 生成的方法
///
/// - `derive()`: Derives key material from input with optional salt and context
/// - `algorithm()`: Returns the algorithm identifier
/// - `clone_box()`: Creates a boxed clone for trait objects
///
/// - `derive()`: 从输入派生密钥材料，可选盐和上下文
/// - `algorithm()`: 返回算法标识符
/// - `clone_box()`: 为 trait 对象创建 boxed 克隆
macro_rules! impl_kdf_key_algorithm {
    ($wrapper:ident, $algo:ty, $algo_enum:expr) => {
        define_wrapper!(@struct_with_algorithm_default, $wrapper, $algo, KdfKeyAlgorithmTrait, {
            fn derive(
                &self,
                ikm: &[u8],
                salt: Option<&[u8]>,
                info: Option<&[u8]>,
                output_len: usize,
            ) -> Result<Zeroizing<Vec<u8>>> {
                self.algorithm
                    .derive(ikm, salt, info, output_len)
                    .map(|k| k.0)
                    .map_err(Error::from)
            }

            fn algorithm(&self) -> KdfKeyAlgorithm {
                $algo_enum
            }

            fn clone_box(&self) -> Box<dyn KdfKeyAlgorithmTrait> {
                Box::new(self.clone())
            }

            fn into_boxed(self) -> Box<dyn KdfKeyAlgorithmTrait> {
                Box::new(self)
            }
        });
    };
}

impl_kdf_key_algorithm!(
    HkdfSha256Wrapper,
    HkdfSha256,
    KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha256)
);

impl_kdf_key_algorithm!(
    HkdfSha384Wrapper,
    HkdfSha384,
    KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha384)
);

impl_kdf_key_algorithm!(
    HkdfSha512Wrapper,
    HkdfSha512,
    KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha512)
);

/// Universal wrapper for key-based KDF algorithms providing runtime algorithm selection.
///
/// 提供运行时算法选择的基于密钥的 KDF 算法通用包装器。
///
/// ## Purpose | 目的
///
/// This wrapper provides a unified interface for all key-based KDF algorithms,
/// allowing runtime algorithm selection while maintaining type safety. It acts
/// as a bridge between algorithm enums and concrete implementations.
///
/// 此包装器为所有基于密钥的 KDF 算法提供统一接口，
/// 允许运行时算法选择同时保持类型安全。它充当算法枚举和具体实现之间的桥梁。
///
/// ## Features | 特性
///
/// - **Runtime Polymorphism**: Switch between algorithms at runtime
/// - **Unified Interface**: Same API for all key-based KDF algorithms
/// - **Memory Safety**: Automatic zeroing of derived key material
/// - **Performance**: Efficient implementation with minimal overhead
///
/// - **运行时多态性**: 在运行时切换算法
/// - **统一接口**: 所有基于密钥的 KDF 算法的相同 API
/// - **内存安全**: 派生密钥材料的自动清零
/// - **性能**: 高效实现，开销最小
///
/// ## Examples | 示例
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::kdf::key::KdfKeyAlgorithm;
/// use seal_crypto_wrapper::wrappers::kdf::key::KdfKeyWrapper;
///
/// // Create from algorithm enum
/// let algorithm = KdfKeyAlgorithm::build().hkdf_sha256();
/// let wrapper = algorithm.into_kdf_key_wrapper();
///
/// // Derive keys from master key
/// let master_key = b"high-entropy-master-key-material";
/// let salt = Some(b"unique-salt".as_slice());
/// let info = Some(b"application-context".as_slice());
///
/// let derived_key = wrapper.derive(master_key, salt, info, 32)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct KdfKeyWrapper {
    algorithm: Box<dyn KdfKeyAlgorithmTrait>,
}

impl KdfKeyAlgorithmTrait for KdfKeyWrapper {
    fn derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.algorithm.derive(ikm, salt, info, output_len)
    }

    fn algorithm(&self) -> KdfKeyAlgorithm {
        self.algorithm.algorithm()
    }

    fn clone_box(&self) -> Box<dyn KdfKeyAlgorithmTrait> {
        self.algorithm.clone_box()
    }

    fn into_boxed(self) -> Box<dyn KdfKeyAlgorithmTrait> {
        Box::new(self)
    }
}

impl KdfKeyWrapper {
    /// Creates a new wrapper from a boxed trait object.
    ///
    /// 从 boxed trait 对象创建新的包装器。
    ///
    /// This constructor allows you to wrap any implementation of
    /// `KdfKeyAlgorithmTrait` in the universal wrapper interface.
    ///
    /// 此构造函数允许您将 `KdfKeyAlgorithmTrait` 的任何实现
    /// 包装在通用包装器接口中。
    ///
    /// ## Arguments | 参数
    ///
    /// * `algorithm` - A boxed trait object implementing the key-based KDF algorithm
    ///
    /// * `algorithm` - 实现基于密钥的 KDF 算法的 boxed trait 对象
    pub fn new(algorithm: Box<dyn KdfKeyAlgorithmTrait>) -> Self {
        Self { algorithm }
    }

    /// Creates a wrapper from a key-based KDF algorithm enum.
    ///
    /// 从基于密钥的 KDF 算法枚举创建包装器。
    ///
    /// This is the most common way to create a wrapper, as it automatically
    /// selects the appropriate concrete implementation based on the algorithm.
    ///
    /// 这是创建包装器的最常见方式，因为它根据算法自动选择适当的具体实现。
    ///
    /// ## Arguments | 参数
    ///
    /// * `algorithm` - The key-based KDF algorithm enum variant
    ///
    /// * `algorithm` - 基于密钥的 KDF 算法枚举变体
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::kdf::key::KdfKeyAlgorithm;
    /// use seal_crypto_wrapper::wrappers::kdf::key::KdfKeyWrapper;
    ///
    /// // Different hash functions for different security levels
    /// let hkdf_sha256 = KdfKeyWrapper::from_enum(
    ///     KdfKeyAlgorithm::build().hkdf_sha256()
    /// );
    ///
    /// let hkdf_sha512 = KdfKeyWrapper::from_enum(
    ///     KdfKeyAlgorithm::build().hkdf_sha512()
    /// );
    /// ```
    pub fn from_enum(algorithm: KdfKeyAlgorithm) -> Self {
        let algorithm: Box<dyn KdfKeyAlgorithmTrait> = match algorithm {
            KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha256) => {
                Box::new(HkdfSha256Wrapper::default())
            }
            KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha384) => {
                Box::new(HkdfSha384Wrapper::default())
            }
            KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha512) => {
                Box::new(HkdfSha512Wrapper::default())
            }
        };
        Self::new(algorithm)
    }
}

impl Deref for KdfKeyWrapper {
    type Target = Box<dyn KdfKeyAlgorithmTrait>;

    fn deref(&self) -> &Self::Target {
        &self.algorithm
    }
}

impl From<KdfKeyAlgorithm> for KdfKeyWrapper {
    fn from(algorithm: KdfKeyAlgorithm) -> Self {
        Self::from_enum(algorithm)
    }
}

impl From<Box<dyn KdfKeyAlgorithmTrait>> for KdfKeyWrapper {
    fn from(algorithm: Box<dyn KdfKeyAlgorithmTrait>) -> Self {
        Self::new(algorithm)
    }
}
