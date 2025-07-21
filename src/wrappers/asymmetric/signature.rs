//! Digital signature algorithm wrappers for authentication and non-repudiation.
//!
//! 用于认证和不可否认性的数字签名算法包装器。
//!
//! ## Overview | 概述
//!
//! This module provides concrete implementations of digital signature algorithms
//! that enable authentication, data integrity verification, and non-repudiation.
//! It supports both traditional and post-quantum signature schemes.
//!
//! 此模块提供数字签名算法的具体实现，启用认证、数据完整性验证和不可否认性。
//! 它支持传统和后量子签名方案。
//!
//! ## Supported Algorithms | 支持的算法
//!
//! ### Traditional Signatures | 传统签名
//! - **Ed25519**: High-performance Edwards curve signatures
//!   - Security Level: 128-bit
//!   - Key Size: 32 bytes (both public and private)
//!   - Signature Size: 64 bytes
//!   - Features: Deterministic, fast verification
//!
//! - **ECDSA P-256**: NIST standard elliptic curve signatures
//!   - Security Level: 128-bit
//!   - Key Size: 32 bytes (private), 64 bytes (public, uncompressed)
//!   - Signature Size: ~64 bytes (variable)
//!   - Features: Widely supported, standards compliant
//!
//! ### Post-Quantum Signatures | 后量子签名
//! - **Dilithium-2**: NIST Level 1 (128-bit security)
//! - **Dilithium-3**: NIST Level 3 (192-bit security)
//! - **Dilithium-5**: NIST Level 5 (256-bit security)
//!
//! ## Signature Operations | 签名操作
//!
//! 1. **Key Generation**: Generate public-private key pair
//! 2. **Signing**: Create digital signature for a message
//! 3. **Verification**: Verify signature authenticity with public key
//!
//! 1. **密钥生成**: 生成公私钥对
//! 2. **签名**: 为消息创建数字签名
//! 3. **验证**: 使用公钥验证签名真实性
//!
//! ## Security Properties | 安全属性
//!
//! - **Unforgeability**: Cannot create valid signatures without private key
//! - **Non-repudiation**: Signatures provide proof of origin
//! - **Message Integrity**: Any message modification invalidates signature
//! - **Authentication**: Verifies identity of message sender
//!
//! - **不可伪造性**: 没有私钥无法创建有效签名
//! - **不可否认性**: 签名提供来源证明
//! - **消息完整性**: 任何消息修改都会使签名无效
//! - **认证**: 验证消息发送者的身份

use crate::algorithms::asymmetric::signature::{DilithiumSecurityLevel, SignatureAlgorithm};
use crate::define_wrapper;
use crate::error::{Error, FormatError, Result};
use crate::keys::asymmetric::signature::{
    TypedSignatureKeyPair, TypedSignaturePrivateKey, TypedSignaturePublicKey,
};
use crate::keys::asymmetric::{TypedAsymmetricPrivateKeyTrait, TypedAsymmetricPublicKeyTrait};
use crate::traits::SignatureAlgorithmTrait;
use seal_crypto::prelude::{AsymmetricKeySet, Key, Signature, Signer, Verifier};
use seal_crypto::schemes::asymmetric::post_quantum::dilithium::{
    Dilithium2, Dilithium3, Dilithium5,
};
use seal_crypto::schemes::asymmetric::traditional::ecc::{EcdsaP256, Ed25519};
use crate::bincode::{Decode, Encode};
use std::ops::Deref;

/// Macro for implementing signature algorithm wrappers.
///
/// 用于实现签名算法包装器的宏。
///
/// This macro generates a complete wrapper implementation for a signature algorithm,
/// including all required trait methods, key validation, and error handling.
/// It ensures type safety by validating that keys match the algorithm.
///
/// 此宏为签名算法生成完整的包装器实现，
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
/// - `sign()`: Creates a digital signature for a message
/// - `verify()`: Verifies a signature against a message
/// - `generate_keypair()`: Generates a new key pair
///
/// - `algorithm()`: 返回算法标识符
/// - `sign()`: 为消息创建数字签名
/// - `verify()`: 验证消息的签名
/// - `generate_keypair()`: 生成新的密钥对
macro_rules! impl_signature_algorithm {
    ($wrapper:ident, $algo:ty, $algo_enum:expr) => {
        define_wrapper!(@unit_struct, $wrapper, SignatureAlgorithmTrait, {
            fn algorithm(&self) -> SignatureAlgorithm {
                $algo_enum
            }

            fn sign(&self, message: &[u8], key: &TypedSignaturePrivateKey) -> Result<SignatureWrapper> {
                if key.algorithm != $algo_enum {
                    return Err(Error::FormatError(FormatError::InvalidKeyType));
                }
                type KT = $algo;
                let sk = <KT as AsymmetricKeySet>::PrivateKey::from_bytes(&key.to_bytes())?;
                let sig = KT::sign(&sk, message)?;
                Ok(SignatureWrapper::new(sig))
            }

            fn verify(
                &self,
                message: &[u8],
                key: &TypedSignaturePublicKey,
                signature: &SignatureWrapper,
            ) -> Result<()> {
                if key.algorithm != $algo_enum {
                    return Err(Error::FormatError(FormatError::InvalidKeyType));
                }
                type KT = $algo;
                let pk = <KT as AsymmetricKeySet>::PublicKey::from_bytes(&key.to_bytes())?;
                KT::verify(&pk, message, signature)?;
                Ok(())
            }

            fn generate_keypair(&self) -> Result<TypedSignatureKeyPair> {
                TypedSignatureKeyPair::generate($algo_enum)
            }

            fn clone_box(&self) -> Box<dyn SignatureAlgorithmTrait> {
                Box::new(self.clone())
            }
        });
    };
}

/// Universal wrapper for signature algorithms providing runtime algorithm selection.
///
/// 提供运行时算法选择的签名算法通用包装器。
///
/// ## Purpose | 目的
///
/// This wrapper provides a unified interface for all signature algorithms,
/// allowing runtime algorithm selection while maintaining type safety. It acts
/// as a bridge between algorithm enums and concrete implementations.
///
/// 此包装器为所有签名算法提供统一接口，允许运行时算法选择同时保持类型安全。
/// 它充当算法枚举和具体实现之间的桥梁。
///
/// ## Features | 特性
///
/// - **Runtime Polymorphism**: Switch between algorithms at runtime
/// - **Type Safety**: Maintains algorithm-key binding verification
/// - **Unified Interface**: Same API for all signature algorithms
/// - **Performance**: Efficient implementation with minimal overhead
///
/// - **运行时多态性**: 在运行时切换算法
/// - **类型安全**: 保持算法-密钥绑定验证
/// - **统一接口**: 所有签名算法的相同 API
/// - **性能**: 高效实现，开销最小
///
/// ## Examples | 示例
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::asymmetric::signature::SignatureAlgorithm;
/// use seal_crypto_wrapper::wrappers::asymmetric::signature::SignatureAlgorithmWrapper;
///
/// // Create from algorithm enum
/// let algorithm = SignatureAlgorithm::build().ed25519();
/// let wrapper = SignatureAlgorithmWrapper::from_enum(algorithm);
///
/// // Generate key pair and sign message
/// let keypair = wrapper.generate_keypair()?;
/// let (public_key, private_key) = keypair.into_keypair();
///
/// let message = b"Hello, World!";
/// let signature = wrapper.sign(message, &private_key)?;
/// wrapper.verify(message, &public_key, signature)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct SignatureAlgorithmWrapper {
    algorithm: Box<dyn SignatureAlgorithmTrait>,
}

impl Deref for SignatureAlgorithmWrapper {
    type Target = Box<dyn SignatureAlgorithmTrait>;

    fn deref(&self) -> &Self::Target {
        &self.algorithm
    }
}

impl SignatureAlgorithmWrapper {
    /// Creates a new wrapper from a boxed trait object.
    ///
    /// 从 boxed trait 对象创建新的包装器。
    ///
    /// This constructor allows you to wrap any implementation of
    /// `SignatureAlgorithmTrait` in the universal wrapper interface.
    ///
    /// 此构造函数允许您将 `SignatureAlgorithmTrait` 的任何实现
    /// 包装在通用包装器接口中。
    ///
    /// ## Arguments | 参数
    ///
    /// * `algorithm` - A boxed trait object implementing the signature algorithm
    ///
    /// * `algorithm` - 实现签名算法的 boxed trait 对象
    pub fn new(algorithm: Box<dyn SignatureAlgorithmTrait>) -> Self {
        Self { algorithm }
    }

    /// Creates a wrapper from a signature algorithm enum.
    ///
    /// 从签名算法枚举创建包装器。
    ///
    /// This is the most common way to create a wrapper, as it automatically
    /// selects the appropriate concrete implementation based on the algorithm.
    ///
    /// 这是创建包装器的最常见方式，因为它根据算法自动选择适当的具体实现。
    ///
    /// ## Arguments | 参数
    ///
    /// * `algorithm` - The signature algorithm enum variant
    ///
    /// * `algorithm` - 签名算法枚举变体
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::asymmetric::signature::SignatureAlgorithm;
    /// use seal_crypto_wrapper::wrappers::asymmetric::signature::SignatureAlgorithmWrapper;
    ///
    /// // Traditional algorithms
    /// let ed25519 = SignatureAlgorithmWrapper::from_enum(
    ///     SignatureAlgorithm::build().ed25519()
    /// );
    ///
    /// let ecdsa = SignatureAlgorithmWrapper::from_enum(
    ///     SignatureAlgorithm::build().ecdsa_p256()
    /// );
    ///
    /// // Post-quantum algorithms
    /// let dilithium = SignatureAlgorithmWrapper::from_enum(
    ///     SignatureAlgorithm::build().dilithium2()
    /// );
    /// ```
    pub fn from_enum(algorithm: SignatureAlgorithm) -> Self {
        let algorithm: Box<dyn SignatureAlgorithmTrait> = match algorithm {
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L2) => {
                Box::new(Dilithium2Wrapper::new())
            }
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L3) => {
                Box::new(Dilithium3Wrapper::new())
            }
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L5) => {
                Box::new(Dilithium5Wrapper::new())
            }
            SignatureAlgorithm::Ed25519 => Box::new(Ed25519Wrapper::new()),
            SignatureAlgorithm::EcdsaP256 => Box::new(EcdsaP256Wrapper::new()),
        };
        Self::new(algorithm)
    }
}

impl SignatureAlgorithmTrait for SignatureAlgorithmWrapper {
    fn sign(&self, message: &[u8], key: &TypedSignaturePrivateKey) -> Result<SignatureWrapper> {
        self.algorithm.sign(message, key)
    }

    fn verify(
        &self,
        message: &[u8],
        key: &TypedSignaturePublicKey,
        signature: &SignatureWrapper,
    ) -> Result<()> {
        self.algorithm.verify(message, key, signature)
    }

    fn generate_keypair(&self) -> Result<TypedSignatureKeyPair> {
        self.algorithm.generate_keypair()
    }

    fn clone_box(&self) -> Box<dyn SignatureAlgorithmTrait> {
        self.algorithm.clone_box()
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm.algorithm()
    }
}

impl From<SignatureAlgorithm> for SignatureAlgorithmWrapper {
    fn from(value: SignatureAlgorithm) -> Self {
        Self::from_enum(value)
    }
}

impl From<Box<dyn SignatureAlgorithmTrait>> for SignatureAlgorithmWrapper {
    fn from(value: Box<dyn SignatureAlgorithmTrait>) -> Self {
        Self::new(value)
    }
}

impl_signature_algorithm!(
    Dilithium2Wrapper,
    Dilithium2,
    SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L2)
);
impl_signature_algorithm!(
    Dilithium3Wrapper,
    Dilithium3,
    SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L3)
);
impl_signature_algorithm!(
    Dilithium5Wrapper,
    Dilithium5,
    SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L5)
);
impl_signature_algorithm!(Ed25519Wrapper, Ed25519, SignatureAlgorithm::Ed25519);
impl_signature_algorithm!(EcdsaP256Wrapper, EcdsaP256, SignatureAlgorithm::EcdsaP256);

#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode, serde::Serialize, serde::Deserialize)]
pub struct SignatureWrapper {
    signature: Signature,
}

impl SignatureWrapper {
    pub(crate) fn new(signature: Signature) -> Self {
        Self { signature }
    }

    pub fn into_signature(self) -> Signature {
        self.signature
    }
}

impl Deref for SignatureWrapper {
    type Target = Signature;

    fn deref(&self) -> &Self::Target {
        &self.signature
    }
}