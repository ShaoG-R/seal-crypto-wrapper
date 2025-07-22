//! Hash algorithm wrappers.
//!
//! 哈希算法包装器。
//!
//! ## Overview | 概述
//!
//! This module provides concrete implementations of hash algorithms.
//! Each wrapper implements the `HashAlgorithmTrait` and provides type-safe access to the
//! underlying cryptographic operations.
//!
//! 此模块提供哈希算法的具体实现。
//! 每个包装器都实现 `HashAlgorithmTrait` 并提供对底层密码操作的类型安全访问。
//!
//! ## Supported Algorithms | 支持的算法
//!
//! - **SHA-256**
//! - **SHA-384**
//! - **SHA-512**
//!
//! ## Key Features | 关键特性
//!
//! ### Type Safety | 类型安全
//! - Runtime compatibility checking
//! - Compile-time algorithm selection
//!
//! ### Security | 安全性
//! - Cryptographically secure hash functions
//! - HMAC for message authentication
//!
//! ## Usage Examples | 使用示例
//!
//! ### Basic Hashing | 基本哈希
//!
//! ```rust
//! use seal_crypto_wrapper::algorithms::hash::HashAlgorithm;
//!
//! let algorithm = HashAlgorithm::build().sha256();
//! let hasher = algorithm.into_wrapper();
//!
//! let data = b"Hello, World!";
//! let digest = hasher.hash(data);
//!
//! // The length of the digest depends on the algorithm
//! assert_eq!(digest.len(), 32);
//! ```
//!
//! ### HMAC Computation | HMAC 计算
//!
//! ```rust
//! # use seal_crypto_wrapper::error::Result;
//! use seal_crypto_wrapper::algorithms::hash::HashAlgorithm;
//!
//! let hasher = HashAlgorithm::build().sha256().into_wrapper();
//! let key = b"my secret key";
//! let message = b"the message to authenticate";
//!
//! let mac = hasher.hmac(key, message)?;
//!
//! assert_eq!(mac.len(), 32);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::algorithms::hash::HashAlgorithm;
use crate::error::{Error, Result};
use crate::traits::HashAlgorithmTrait;
use seal_crypto::prelude::Hasher;
use seal_crypto::schemes::hash::{Sha256, Sha384, Sha512};
use std::ops::Deref;

/// Macro for implementing hash algorithm wrappers.
///
/// 用于实现哈希算法包装器的宏。
///
/// This macro generates a complete wrapper implementation for a hash algorithm,
/// including all required trait methods and error handling.
///
/// 此宏为哈希算法生成完整的包装器实现，
/// 包括所有必需的 trait 方法和错误处理。
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
macro_rules! impl_hash_algorithm {
    ($wrapper:ident, $algo:ty, $algo_enum:expr) => {
        /// Wrapper implementation for a specific hash algorithm.
        ///
        /// 特定哈希算法的包装器实现。
        ///
        /// This struct provides a type-safe interface to the underlying cryptographic
        /// algorithm, ensuring operations are performed with the correct parameters.
        ///
        /// 此结构体为底层密码算法提供类型安全接口，
        /// 确保使用正确的参数执行操作。
        #[derive(Clone, Debug, Default)]
        pub struct $wrapper;

        impl $wrapper {
            pub fn new() -> Self {
                Self
            }
        }

        impl From<$wrapper> for Box<dyn HashAlgorithmTrait> {
            fn from(wrapper: $wrapper) -> Self {
                Box::new(wrapper)
            }
        }

        impl HashAlgorithmTrait for $wrapper {
            fn hash(&self, data: &[u8]) -> Vec<u8> {
                <$algo>::hash(data)
            }

            fn hmac(&self, key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
                <$algo>::hmac(key, msg).map_err(Error::from)
            }

            fn clone_box(&self) -> Box<dyn HashAlgorithmTrait> {
                Box::new(self.clone())
            }

            fn algorithm(&self) -> HashAlgorithm {
                $algo_enum
            }

            fn into_boxed(self) -> Box<dyn HashAlgorithmTrait> {
                Box::new(self)
            }
        }
    };
}

/// Universal wrapper for hash algorithms.
///
/// 哈希算法的通用包装器。
///
/// ## Purpose | 目的
///
/// This wrapper provides a unified interface for all hash algorithms,
/// allowing runtime algorithm selection while maintaining type safety. It acts as
/// a bridge between algorithm enums and concrete implementations.
///
/// 此包装器为所有哈希算法提供统一接口，
/// 允许运行时算法选择同时保持类型安全。它充当算法枚举和具体实现之间的桥梁。
///
/// ## Features | 特性
///
/// - **Runtime Polymorphism**: Switch between algorithms at runtime
/// - **Unified Interface**: Same API for all hash algorithms
///
/// - **运行时多态性**: 在运行时切换算法
/// - **统一接口**: 所有哈希算法的相同 API
///
/// ## Examples | 示例
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::hash::HashAlgorithm;
/// use seal_crypto_wrapper::wrappers::hash::HashAlgorithmWrapper;
///
/// // Create from algorithm enum
/// let algorithm = HashAlgorithm::build().sha256();
/// let wrapper = HashAlgorithmWrapper::from_enum(algorithm);
///
/// // Use unified interface
/// let digest = wrapper.hash(b"Hello, World!");
/// ```
#[derive(Clone, Debug)]
pub struct HashAlgorithmWrapper {
    pub(crate) algorithm: Box<dyn HashAlgorithmTrait>,
}

impl Deref for HashAlgorithmWrapper {
    type Target = Box<dyn HashAlgorithmTrait>;

    fn deref(&self) -> &Self::Target {
        &self.algorithm
    }
}

impl Into<Box<dyn HashAlgorithmTrait>> for HashAlgorithmWrapper {
    fn into(self) -> Box<dyn HashAlgorithmTrait> {
        self.algorithm
    }
}

impl HashAlgorithmWrapper {
    /// Creates a new wrapper from a boxed trait object.
    ///
    /// 从 boxed trait 对象创建新的包装器。
    ///
    /// This constructor allows you to wrap any implementation of
    /// `HashAlgorithmTrait` in the universal wrapper interface.
    ///
    /// 此构造函数允许您将 `HashAlgorithmTrait` 的任何实现
    /// 包装在通用包装器接口中。
    ///
    /// ## Arguments | 参数
    ///
    /// * `algorithm` - A boxed trait object implementing the hash algorithm
    ///
    /// * `algorithm` - 实现哈希算法的 boxed trait 对象
    pub fn new(algorithm: Box<dyn HashAlgorithmTrait>) -> Self {
        Self { algorithm }
    }

    /// Creates a wrapper from a hash algorithm enum.
    ///
    /// 从哈希算法枚举创建包装器。
    ///
    /// This is the most common way to create a wrapper, as it automatically
    /// selects the appropriate concrete implementation based on the algorithm.
    ///
    /// 这是创建包装器的最常见方式，因为它根据算法自动选择适当的具体实现。
    ///
    /// ## Arguments | 参数
    ///
    /// * `algorithm` - The hash algorithm enum variant
    ///
    /// * `algorithm` - 哈希算法枚举变体
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::hash::HashAlgorithm;
    /// use seal_crypto_wrapper::wrappers::hash::HashAlgorithmWrapper;
    ///
    /// let sha256 = HashAlgorithmWrapper::from_enum(
    ///     HashAlgorithm::build().sha256()
    /// );
    ///
    /// let sha512 = HashAlgorithmWrapper::from_enum(
    ///     HashAlgorithm::build().sha512()
    /// );
    /// ```
    pub fn from_enum(algorithm: HashAlgorithm) -> Self {
        let algorithm: Box<dyn HashAlgorithmTrait> = match algorithm {
            HashAlgorithm::Sha256 => Box::new(Hash256Wrapper::new()),
            HashAlgorithm::Sha384 => Box::new(Hash384Wrapper::new()),
            HashAlgorithm::Sha512 => Box::new(Hash512Wrapper::new()),
        };
        Self::new(algorithm)
    }
}

impl HashAlgorithmTrait for HashAlgorithmWrapper {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        self.algorithm.hash(data)
    }

    fn hmac(&self, key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        self.algorithm.hmac(key, msg)
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.algorithm.algorithm()
    }

    fn clone_box(&self) -> Box<dyn HashAlgorithmTrait> {
        Box::new(self.clone())
    }

    fn into_boxed(self) -> Box<dyn HashAlgorithmTrait> {
        self.algorithm
    }
}

impl From<HashAlgorithm> for HashAlgorithmWrapper {
    fn from(algorithm: HashAlgorithm) -> Self {
        Self::from_enum(algorithm)
    }
}

impl From<Box<dyn HashAlgorithmTrait>> for HashAlgorithmWrapper {
    fn from(algorithm: Box<dyn HashAlgorithmTrait>) -> Self {
        Self::new(algorithm)
    }
}

impl_hash_algorithm!(Hash256Wrapper, Sha256, HashAlgorithm::Sha256);
impl_hash_algorithm!(Hash384Wrapper, Sha384, HashAlgorithm::Sha384);
impl_hash_algorithm!(Hash512Wrapper, Sha512, HashAlgorithm::Sha512);
