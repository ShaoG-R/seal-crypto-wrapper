//! Key Encapsulation Mechanism (KEM) algorithm wrappers for secure key establishment.
//!
//! 用于安全密钥建立的密钥封装机制 (KEM) 算法包装器。
//!
//! ## Overview | 概述
//!
//! This module provides concrete implementations of KEM algorithms that enable
//! secure establishment of shared secrets between parties. KEMs are essential
//! for hybrid encryption schemes and post-quantum cryptography.
//!
//! 此模块提供 KEM 算法的具体实现，使各方之间能够安全建立共享密钥。
//! KEM 对混合加密方案和后量子密码学至关重要。
//!
//! ## Supported Algorithms | 支持的算法
//!
//! ### Traditional KEMs | 传统 KEM
//! - **RSA-2048**: 2048-bit RSA with SHA-256/384/512
//! - **RSA-4096**: 4096-bit RSA with SHA-256/384/512
//!
//! ### Post-Quantum KEMs | 后量子 KEM
//! - **Kyber-512**: NIST Level 1 (128-bit security)
//! - **Kyber-768**: NIST Level 3 (192-bit security)
//! - **Kyber-1024**: NIST Level 5 (256-bit security)
//!
//! ## KEM Operations | KEM 操作
//!
//! 1. **Key Generation**: Generate public-private key pair
//! 2. **Encapsulation**: Use public key to generate shared secret + ciphertext
//! 3. **Decapsulation**: Use private key to recover shared secret from ciphertext
//!
//! 1. **密钥生成**: 生成公私钥对
//! 2. **封装**: 使用公钥生成共享密钥 + 密文
//! 3. **解封装**: 使用私钥从密文中恢复共享密钥
//!
//! ## Security Properties | 安全属性
//!
//! - **IND-CCA2**: Indistinguishability under adaptive chosen ciphertext attack
//! - **Forward Secrecy**: When used with ephemeral keys
//! - **Post-Quantum Security**: Kyber variants resist quantum attacks
//!
//! - **IND-CCA2**: 在自适应选择密文攻击下的不可区分性
//! - **前向保密**: 与临时密钥一起使用时
//! - **后量子安全**: Kyber 变体抵抗量子攻击

use crate::algorithms::{
    asymmetric::kem::{KemAlgorithm, KyberSecurityLevel, RsaBits},
    HashAlgorithmEnum,
};
use crate::error::{Error, FormatError, Result};
use crate::traits::KemAlgorithmTrait;
use seal_crypto::prelude::{AsymmetricKeySet, Kem, Key};
use seal_crypto::schemes::asymmetric::post_quantum::kyber::{Kyber1024, Kyber512, Kyber768};
use seal_crypto::schemes::asymmetric::traditional::rsa::{Rsa2048, Rsa4096};
use seal_crypto::schemes::hash::{Sha256, Sha384, Sha512};
use std::ops::Deref;
use crate::keys::asymmetric::kem::{TypedKemKeyPair, TypedKemPrivateKey, TypedKemPublicKey};
use crate::define_wrapper;
use crate::keys::asymmetric::{TypedAsymmetricPrivateKeyTrait, TypedAsymmetricPublicKeyTrait};
use crate::keys::asymmetric::kem::{SharedSecret, EncapsulatedKey};

/// Macro for implementing KEM algorithm wrappers.
///
/// 用于实现 KEM 算法包装器的宏。
///
/// This macro generates a complete wrapper implementation for a KEM algorithm,
/// including all required trait methods, key validation, and error handling.
/// It ensures type safety by validating that keys match the algorithm.
///
/// 此宏为 KEM 算法生成完整的包装器实现，
/// 包括所有必需的 trait 方法、密钥验证和错误处理。
/// 它通过验证密钥与算法匹配来确保类型安全。
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
/// - `algorithm()`: Returns the algorithm identifier
/// - `encapsulate_key()`: Performs key encapsulation
/// - `decapsulate_key()`: Performs key decapsulation
/// - `generate_keypair()`: Generates a new key pair
///
/// - `algorithm()`: 返回算法标识符
/// - `encapsulate_key()`: 执行密钥封装
/// - `decapsulate_key()`: 执行密钥解封装
/// - `generate_keypair()`: 生成新的密钥对
macro_rules! impl_kem_algorithm {
    ($wrapper:ident, $algo:ty, $algo_enum:expr) => {
        define_wrapper!(@unit_struct, $wrapper, KemAlgorithmTrait, {
            fn algorithm(&self) -> KemAlgorithm {
                $algo_enum
            }

            fn encapsulate_key(
                &self,
                public_key: &TypedKemPublicKey,
            ) -> Result<(SharedSecret, EncapsulatedKey)> {
                if public_key.algorithm != $algo_enum {
                    return Err(Error::FormatError(FormatError::InvalidKeyType));
                }
                type KT = $algo;
                let pk = <KT as AsymmetricKeySet>::PublicKey::from_bytes(&public_key.to_bytes())?;
                KT::encapsulate(&pk).map_err(Error::from).map(|(shared_secret, ciphertext)| (SharedSecret(shared_secret), EncapsulatedKey { key: ciphertext, algorithm: $algo_enum }))
            }

            fn decapsulate_key(
                &self,
                private_key: &TypedKemPrivateKey,
                encapsulated_key: &EncapsulatedKey,
            ) -> Result<SharedSecret> {
                if private_key.algorithm != $algo_enum || encapsulated_key.algorithm != $algo_enum {
                    return Err(Error::FormatError(FormatError::InvalidKeyType));
                }
                type KT = $algo;
                let sk = <KT as AsymmetricKeySet>::PrivateKey::from_bytes(&private_key.to_bytes())?;
                KT::decapsulate(&sk, &encapsulated_key.key).map_err(Error::from).map(SharedSecret)
            }

            fn generate_keypair(&self) -> Result<TypedKemKeyPair> {
                TypedKemKeyPair::generate($algo_enum)
            }

            fn clone_box_asymmetric(&self) -> Box<dyn KemAlgorithmTrait> {
                Box::new(self.clone())
            }

            fn into_asymmetric_boxed(self) -> Box<dyn KemAlgorithmTrait> {
                Box::new(self)
            }
        });
    };
}

/// Universal wrapper for KEM algorithms providing runtime algorithm selection.
///
/// 提供运行时算法选择的 KEM 算法通用包装器。
///
/// ## Purpose | 目的
///
/// This wrapper provides a unified interface for all KEM algorithms, allowing
/// runtime algorithm selection while maintaining type safety. It acts as a
/// bridge between algorithm enums and concrete implementations.
///
/// 此包装器为所有 KEM 算法提供统一接口，允许运行时算法选择同时保持类型安全。
/// 它充当算法枚举和具体实现之间的桥梁。
///
/// ## Features | 特性
///
/// - **Runtime Polymorphism**: Switch between algorithms at runtime
/// - **Type Safety**: Maintains algorithm-key binding verification
/// - **Unified Interface**: Same API for all KEM algorithms
/// - **Performance**: Zero-cost abstractions where possible
///
/// - **运行时多态性**: 在运行时切换算法
/// - **类型安全**: 保持算法-密钥绑定验证
/// - **统一接口**: 所有 KEM 算法的相同 API
/// - **性能**: 尽可能的零成本抽象
///
/// ## Examples | 示例
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::asymmetric::kem::KemAlgorithm;
/// use seal_crypto_wrapper::wrappers::asymmetric::kem::KemAlgorithmWrapper;
///
/// // Create from algorithm enum
/// let algorithm = KemAlgorithm::build().kyber512();
/// let wrapper = KemAlgorithmWrapper::from_enum(algorithm);
///
/// // Use unified interface
/// let keypair = wrapper.generate_keypair()?;
/// let (public_key, private_key) = keypair.into_keypair();
/// let (shared_secret, ciphertext) = wrapper.encapsulate_key(&public_key)?;
/// let recovered_secret = wrapper.decapsulate_key(&private_key, &ciphertext)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct KemAlgorithmWrapper {
    pub(crate) algorithm: Box<dyn KemAlgorithmTrait>,
}

impl Deref for KemAlgorithmWrapper {
    type Target = Box<dyn KemAlgorithmTrait>;

    fn deref(&self) -> &Self::Target {
        &self.algorithm
    }
}

impl Into<Box<dyn KemAlgorithmTrait>> for KemAlgorithmWrapper {
    fn into(self) -> Box<dyn KemAlgorithmTrait> {
        self.algorithm
    }
}

impl KemAlgorithmWrapper {
    /// Creates a new wrapper from a boxed trait object.
    ///
    /// 从 boxed trait 对象创建新的包装器。
    ///
    /// This constructor allows you to wrap any implementation of
    /// `KemAlgorithmTrait` in the universal wrapper interface.
    ///
    /// 此构造函数允许您将 `KemAlgorithmTrait` 的任何实现
    /// 包装在通用包装器接口中。
    ///
    /// ## Arguments | 参数
    ///
    /// * `algorithm` - A boxed trait object implementing the KEM algorithm
    ///
    /// * `algorithm` - 实现 KEM 算法的 boxed trait 对象
    pub fn new(algorithm: Box<dyn KemAlgorithmTrait>) -> Self {
        Self { algorithm }
    }

    /// Creates a wrapper from a KEM algorithm enum.
    ///
    /// 从 KEM 算法枚举创建包装器。
    ///
    /// This is the most common way to create a wrapper, as it automatically
    /// selects the appropriate concrete implementation based on the algorithm.
    ///
    /// 这是创建包装器的最常见方式，因为它根据算法自动选择适当的具体实现。
    ///
    /// ## Arguments | 参数
    ///
    /// * `algorithm` - The KEM algorithm enum variant
    ///
    /// * `algorithm` - KEM 算法枚举变体
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::asymmetric::kem::KemAlgorithm;
    /// use seal_crypto_wrapper::wrappers::asymmetric::kem::KemAlgorithmWrapper;
    ///
    /// let kyber = KemAlgorithmWrapper::from_enum(
    ///     KemAlgorithm::build().kyber512()
    /// );
    ///
    /// let rsa = KemAlgorithmWrapper::from_enum(
    ///     KemAlgorithm::build().rsa2048().sha256()
    /// );
    /// ```
    pub fn from_enum(algorithm: KemAlgorithm) -> Self {
        let algorithm: Box<dyn KemAlgorithmTrait> = match algorithm {
            KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha256) => {
                Box::new(Rsa2048Sha256Wrapper::new())
            }
            KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha384) => {
                Box::new(Rsa2048Sha384Wrapper::new())
            }
            KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha512) => {
                Box::new(Rsa2048Sha512Wrapper::new())
            }
            KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha256) => {
                Box::new(Rsa4096Sha256Wrapper::new())
            }
            KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha384) => {
                Box::new(Rsa4096Sha384Wrapper::new())
            }
            KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha512) => {
                Box::new(Rsa4096Sha512Wrapper::new())
            }
            KemAlgorithm::Kyber(KyberSecurityLevel::L512) => {
                Box::new(Kyber512Wrapper::new())
            }
            KemAlgorithm::Kyber(KyberSecurityLevel::L768) => {
                Box::new(Kyber768Wrapper::new())
            }
            KemAlgorithm::Kyber(KyberSecurityLevel::L1024) => {
                Box::new(Kyber1024Wrapper::new())
            }
        };
        Self::new(algorithm)
    }

    pub fn generate_keypair(&self) -> Result<TypedKemKeyPair> {
        self.algorithm.generate_keypair()
    }
}

impl KemAlgorithmTrait for KemAlgorithmWrapper {
    fn algorithm(&self) -> KemAlgorithm {
        self.algorithm.algorithm()
    }

    fn encapsulate_key(
        &self,
        public_key: &TypedKemPublicKey,
    ) -> Result<(SharedSecret, EncapsulatedKey)> {
        self.algorithm.encapsulate_key(public_key)
    }

    fn decapsulate_key(
        &self,
        private_key: &TypedKemPrivateKey,
        encapsulated_key: &EncapsulatedKey,
    ) -> Result<SharedSecret> {
        self.algorithm
            .decapsulate_key(private_key, encapsulated_key)
    }

    fn generate_keypair(&self) -> Result<TypedKemKeyPair> {
        self.algorithm.generate_keypair()
    }

    fn clone_box_asymmetric(&self) -> Box<dyn KemAlgorithmTrait> {
        self.algorithm.clone_box_asymmetric()
    }

    fn into_asymmetric_boxed(self) -> Box<dyn KemAlgorithmTrait> {
        self.algorithm
    }
}

impl From<KemAlgorithm> for KemAlgorithmWrapper {
    fn from(algorithm: KemAlgorithm) -> Self {
        Self::from_enum(algorithm)
    }
}

impl From<Box<dyn KemAlgorithmTrait>> for KemAlgorithmWrapper {
    fn from(algorithm: Box<dyn KemAlgorithmTrait>) -> Self {
        Self::new(algorithm)
    }
}

impl_kem_algorithm!(
    Rsa2048Sha256Wrapper,
    Rsa2048<Sha256>,
    KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha256)
);

impl_kem_algorithm!(
    Rsa2048Sha384Wrapper,
    Rsa2048<Sha384>,
    KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha384)
);

impl_kem_algorithm!(
    Rsa2048Sha512Wrapper,
    Rsa2048<Sha512>,
    KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha512)
);

impl_kem_algorithm!(
    Rsa4096Sha256Wrapper,
    Rsa4096<Sha256>,
    KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha256)
);

impl_kem_algorithm!(
    Rsa4096Sha384Wrapper,
    Rsa4096<Sha384>,
    KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha384)
);

impl_kem_algorithm!(
    Rsa4096Sha512Wrapper,
    Rsa4096<Sha512>,
    KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha512)
);

impl_kem_algorithm!(
    Kyber512Wrapper,
    Kyber512,
    KemAlgorithm::Kyber(KyberSecurityLevel::L512)
);

impl_kem_algorithm!(
    Kyber768Wrapper,
    Kyber768,
    KemAlgorithm::Kyber(KyberSecurityLevel::L768)
);

impl_kem_algorithm!(
    Kyber1024Wrapper,
    Kyber1024,
    KemAlgorithm::Kyber(KyberSecurityLevel::L1024)
);
