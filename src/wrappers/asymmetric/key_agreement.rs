//! Key agreement algorithm wrappers for secure shared secret establishment.
//!
//! 用于安全共享密钥建立的密钥协商算法包装器。
//!
//! ## Overview | 概述
//!
//! This module provides concrete implementations of key agreement algorithms that
//! allow two or more parties to establish a shared secret over an insecure channel.
//! The shared secret can then be used for symmetric encryption or other cryptographic
//! operations requiring a common key.
//!
//! 此模块提供密钥协商算法的具体实现，允许两方或多方通过不安全通道建立共享密钥。
//! 然后可以将共享密钥用于对称加密或其他需要公共密钥的密码操作。
//!
//! ## Supported Algorithms | 支持的算法
//!
//! - **ECDH P-256**: Elliptic Curve Diffie-Hellman over NIST P-256 curve
//!   - Security Level: 128-bit
//!   - Key Size: 32 bytes (private), 64 bytes (public, uncompressed)
//!   - Shared Secret Size: 32 bytes
//!   - Performance: High
//!
//! ## Key Agreement Process | 密钥协商过程
//!
//! 1. **Key Generation**: Each party generates a key pair
//! 2. **Key Exchange**: Parties exchange public keys
//! 3. **Secret Derivation**: Each party derives the same shared secret
//! 4. **Key Derivation**: Use proper KDF to derive actual encryption keys
//!
//! 1. **密钥生成**: 每一方生成密钥对
//! 2. **密钥交换**: 各方交换公钥
//! 3. **密钥派生**: 每一方派生相同的共享密钥
//! 4. **密钥派生**: 使用适当的 KDF 派生实际的加密密钥
//!
//! ## Security Properties | 安全属性
//!
//! - **Computational Diffie-Hellman**: Security based on discrete logarithm problem
//! - **Forward Secrecy**: When using ephemeral keys
//! - **Perfect Forward Secrecy**: When ephemeral keys are properly deleted
//! - **No Authentication**: Key agreement alone doesn't provide authentication
//!
//! - **计算 Diffie-Hellman**: 基于离散对数问题的安全性
//! - **前向保密**: 使用临时密钥时
//! - **完美前向保密**: 临时密钥被正确删除时
//! - **无认证**: 密钥协商本身不提供认证

use crate::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;
use crate::error::{Error, Result};
use crate::keys::asymmetric::key_agreement::{
    TypedKeyAgreementKeyPair, TypedKeyAgreementPrivateKey, TypedKeyAgreementPublicKey,
};
use crate::traits::KeyAgreementAlgorithmTrait;
use seal_crypto::prelude::{AsymmetricKeySet, Key, KeyAgreement};
use seal_crypto::schemes::asymmetric::traditional::ecdh::EcdhP256;
use seal_crypto::zeroize::Zeroizing;
use std::ops::Deref;
use crate::define_wrapper;
use crate::keys::asymmetric::{TypedAsymmetricPrivateKeyTrait, TypedAsymmetricPublicKeyTrait};

/// Macro for implementing key agreement algorithm wrappers.
///
/// 用于实现密钥协商算法包装器的宏。
///
/// This macro generates a complete wrapper implementation for a key agreement algorithm,
/// including all required trait methods, key validation, and error handling.
/// It ensures type safety by validating that keys match the algorithm.
///
/// 此宏为密钥协商算法生成完整的包装器实现，
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
/// - `agree()`: Performs key agreement to derive shared secret
/// - `generate_keypair()`: Generates a new key pair
/// - `clone_box()`: Creates a boxed clone
///
/// - `algorithm()`: 返回算法标识符
/// - `agree()`: 执行密钥协商以派生共享密钥
/// - `generate_keypair()`: 生成新的密钥对
/// - `clone_box()`: 创建 boxed 克隆
macro_rules! impl_key_agreement_algorithm {
    ($wrapper:ident, $algo:ty, $algo_enum:expr) => {
        define_wrapper!(@unit_struct, $wrapper, KeyAgreementAlgorithmTrait, {
            fn algorithm(&self) -> KeyAgreementAlgorithm {
                $algo_enum
            }

            fn agree(
                &self,
                sk: &TypedKeyAgreementPrivateKey,
                pk: &TypedKeyAgreementPublicKey,
            ) -> Result<Zeroizing<Vec<u8>>> {
                if sk.algorithm != $algo_enum || pk.algorithm != $algo_enum {
                    return Err(Error::FormatError(
                        crate::error::FormatError::InvalidKeyType,
                    ));
                }
                type KT = $algo;
                let private_key =
                    <KT as AsymmetricKeySet>::PrivateKey::from_bytes(&sk.to_bytes())?;
                let public_key =
                    <KT as AsymmetricKeySet>::PublicKey::from_bytes(&pk.to_bytes())?;
                let shared_secret = KT::agree(&private_key, &public_key)?;
                Ok(shared_secret)
            }

            fn generate_keypair(&self) -> Result<TypedKeyAgreementKeyPair> {
                TypedKeyAgreementKeyPair::generate($algo_enum)
            }

            fn clone_box(&self) -> Box<dyn KeyAgreementAlgorithmTrait> {
                Box::new(self.clone())
            }
        });
    };
}

/// Universal wrapper for key agreement algorithms providing runtime algorithm selection.
///
/// 提供运行时算法选择的密钥协商算法通用包装器。
///
/// ## Purpose | 目的
///
/// This wrapper provides a unified interface for all key agreement algorithms,
/// allowing runtime algorithm selection while maintaining type safety. It acts
/// as a bridge between algorithm enums and concrete implementations.
///
/// 此包装器为所有密钥协商算法提供统一接口，允许运行时算法选择同时保持类型安全。
/// 它充当算法枚举和具体实现之间的桥梁。
///
/// ## Features | 特性
///
/// - **Runtime Polymorphism**: Switch between algorithms at runtime
/// - **Type Safety**: Maintains algorithm-key binding verification
/// - **Unified Interface**: Same API for all key agreement algorithms
/// - **Performance**: Efficient implementation with minimal overhead
///
/// - **运行时多态性**: 在运行时切换算法
/// - **类型安全**: 保持算法-密钥绑定验证
/// - **统一接口**: 所有密钥协商算法的相同 API
/// - **性能**: 高效实现，开销最小
///
/// ## Examples | 示例
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;
/// use seal_crypto_wrapper::wrappers::asymmetric::key_agreement::KeyAgreementAlgorithmWrapper;
///
/// // Create from algorithm enum
/// let algorithm = KeyAgreementAlgorithm::build().ecdh_p256();
/// let wrapper = KeyAgreementAlgorithmWrapper::from_enum(algorithm);
///
/// // Generate key pairs for Alice and Bob
/// let alice_keypair = wrapper.generate_keypair()?;
/// let bob_keypair = wrapper.generate_keypair()?;
///
/// // Derive shared secrets
/// let (alice_public, alice_private) = alice_keypair.into_keypair();
/// let (bob_public, bob_private) = bob_keypair.into_keypair();
///
/// let alice_shared = wrapper.agree(&alice_private, &bob_public)?;
/// let bob_shared = wrapper.agree(&bob_private, &alice_public)?;
/// assert_eq!(alice_shared, bob_shared);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct KeyAgreementAlgorithmWrapper {
    algorithm: Box<dyn KeyAgreementAlgorithmTrait>,
}

impl Deref for KeyAgreementAlgorithmWrapper {
    type Target = Box<dyn KeyAgreementAlgorithmTrait>;

    fn deref(&self) -> &Self::Target {
        &self.algorithm
    }
}

impl KeyAgreementAlgorithmWrapper {
    /// Creates a new wrapper from a boxed trait object.
    ///
    /// 从 boxed trait 对象创建新的包装器。
    ///
    /// This constructor allows you to wrap any implementation of
    /// `KeyAgreementAlgorithmTrait` in the universal wrapper interface.
    ///
    /// 此构造函数允许您将 `KeyAgreementAlgorithmTrait` 的任何实现
    /// 包装在通用包装器接口中。
    ///
    /// ## Arguments | 参数
    ///
    /// * `algorithm` - A boxed trait object implementing the key agreement algorithm
    ///
    /// * `algorithm` - 实现密钥协商算法的 boxed trait 对象
    pub fn new(algorithm: Box<dyn KeyAgreementAlgorithmTrait>) -> Self {
        Self { algorithm }
    }

    /// Creates a wrapper from a key agreement algorithm enum.
    ///
    /// 从密钥协商算法枚举创建包装器。
    ///
    /// This is the most common way to create a wrapper, as it automatically
    /// selects the appropriate concrete implementation based on the algorithm.
    ///
    /// 这是创建包装器的最常见方式，因为它根据算法自动选择适当的具体实现。
    ///
    /// ## Arguments | 参数
    ///
    /// * `algorithm` - The key agreement algorithm enum variant
    ///
    /// * `algorithm` - 密钥协商算法枚举变体
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;
    /// use seal_crypto_wrapper::wrappers::asymmetric::key_agreement::KeyAgreementAlgorithmWrapper;
    ///
    /// let ecdh = KeyAgreementAlgorithmWrapper::from_enum(
    ///     KeyAgreementAlgorithm::build().ecdh_p256()
    /// );
    ///
    /// // Use for key agreement
    /// let alice_keypair = ecdh.generate_keypair()?;
    /// let bob_keypair = ecdh.generate_keypair()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_enum(algorithm: KeyAgreementAlgorithm) -> Self {
        let algorithm: Box<dyn KeyAgreementAlgorithmTrait> = match algorithm {
            KeyAgreementAlgorithm::EcdhP256 => Box::new(EcdhP256Wrapper::new()),
        };
        Self::new(algorithm)
    }
}

impl KeyAgreementAlgorithmTrait for KeyAgreementAlgorithmWrapper {
    fn agree(
        &self,
        sk: &TypedKeyAgreementPrivateKey,
        pk: &TypedKeyAgreementPublicKey,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.algorithm.agree(sk, pk)
    }

    fn generate_keypair(&self) -> Result<TypedKeyAgreementKeyPair> {
        self.algorithm.generate_keypair()
    }

    fn clone_box(&self) -> Box<dyn KeyAgreementAlgorithmTrait> {
        self.algorithm.clone_box()
    }

    fn algorithm(&self) -> KeyAgreementAlgorithm {
        self.algorithm.algorithm()
    }
}

impl From<KeyAgreementAlgorithm> for KeyAgreementAlgorithmWrapper {
    fn from(value: KeyAgreementAlgorithm) -> Self {
        Self::from_enum(value)
    }
}

impl From<Box<dyn KeyAgreementAlgorithmTrait>> for KeyAgreementAlgorithmWrapper {
    fn from(value: Box<dyn KeyAgreementAlgorithmTrait>) -> Self {
        Self::new(value)
    }
}

impl_key_agreement_algorithm!(EcdhP256Wrapper, EcdhP256, KeyAgreementAlgorithm::EcdhP256);
