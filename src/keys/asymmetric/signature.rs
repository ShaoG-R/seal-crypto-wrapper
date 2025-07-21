//! Digital signature key types and operations.
//!
//! 数字签名密钥类型和操作。
//!
//! ## Overview | 概述
//!
//! This module provides type-safe key management for digital signature algorithms,
//! which are used for authentication, non-repudiation, and data integrity verification.
//! It supports both traditional and post-quantum signature schemes.
//!
//! 此模块为数字签名算法提供类型安全的密钥管理，
//! 用于认证、不可否认性和数据完整性验证。它支持传统和后量子签名方案。
//!
//! ## Signature Operations | 签名操作
//!
//! ### Key Generation | 密钥生成
//! Generate a public-private key pair for the signature algorithm.
//!
//! 为签名算法生成公私钥对。
//!
//! ### Signing | 签名
//! Use the private key to create a digital signature for a message.
//!
//! 使用私钥为消息创建数字签名。
//!
//! ### Verification | 验证
//! Use the public key to verify that a signature was created by the corresponding private key.
//!
//! 使用公钥验证签名是否由相应的私钥创建。
//!
//! ## Supported Algorithms | 支持的算法
//!
//! ### Traditional Algorithms | 传统算法
//! - **Ed25519**: High-performance Edwards curve signatures
//! - **ECDSA P-256**: NIST standard elliptic curve signatures
//!
//! ### Post-Quantum Algorithms | 后量子算法
//! - **Dilithium**: Lattice-based signatures (NIST standardized)
//!   - Dilithium-2: 128-bit security level
//!   - Dilithium-3: 192-bit security level
//!   - Dilithium-5: 256-bit security level
//!
//! ## Security Considerations | 安全考虑
//!
//! - **Private Key Protection**: Private keys must be kept secret and secure
//! - **Algorithm Binding**: Keys are bound to specific algorithms to prevent misuse
//! - **Message Integrity**: Signatures provide both authentication and integrity
//! - **Non-Repudiation**: Valid signatures provide proof of origin
//!
//! - **私钥保护**: 私钥必须保密和安全
//! - **算法绑定**: 密钥绑定到特定算法以防止误用
//! - **消息完整性**: 签名提供认证和完整性
//! - **不可否认性**: 有效签名提供来源证明
//!
//! ## Examples | 示例
//!
//! ```rust
//! use seal_crypto_wrapper::algorithms::asymmetric::AsymmetricAlgorithm;
//!
//! // Generate signature key pair
//! let algorithm = AsymmetricAlgorithm::build().signature().ed25519();
//! let signer = algorithm.into_signature_wrapper();
//! let keypair = signer.generate_keypair()?;
//!
//! // Separate keys
//! let (public_key, private_key) = keypair.into_keypair();
//!
//! // Sign a message
//! let message = b"Hello, World!";
//! let signature = signer.sign(message, &private_key)?;
//!
//! // Verify the signature
//! signer.verify(message, &public_key, signature)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::algorithms::asymmetric::signature::SignatureAlgorithm;
use crate::dispatch_signature;
use crate::error::Error;
use crate::impl_typed_asymmetric_private_key;
use crate::impl_typed_asymmetric_public_key;
use crate::keys::asymmetric::{AsymmetricPrivateKey, AsymmetricPublicKey};
use seal_crypto::prelude::{Key, KeyGenerator};

/// Algorithm-bound signature key pair for digital signature operations.
///
/// 用于数字签名操作的算法绑定签名密钥对。
///
/// ## Purpose | 目的
///
/// This type represents a complete signature key pair (public and private keys) that is
/// bound to a specific signature algorithm. It ensures that both keys can only be used
/// with the algorithm they were generated for, preventing cryptographic misuse.
///
/// 此类型表示绑定到特定签名算法的完整签名密钥对（公钥和私钥）。
/// 它确保两个密钥只能与生成它们的算法一起使用，防止密码误用。
///
/// ## Key Features | 关键特性
///
/// - **Algorithm Binding**: Both keys are bound to the same signature algorithm
/// - **Type Safety**: Prevents using keys with incompatible algorithms
/// - **Serialization**: Supports secure serialization with algorithm metadata
/// - **Memory Safety**: Private key material is automatically zeroed on drop
///
/// - **算法绑定**: 两个密钥都绑定到相同的签名算法
/// - **类型安全**: 防止将密钥与不兼容的算法一起使用
/// - **序列化**: 支持带算法元数据的安全序列化
/// - **内存安全**: 私钥材料在丢弃时自动清零
///
/// ## Usage Pattern | 使用模式
///
/// ```rust
/// use seal_crypto_wrapper::keys::asymmetric::signature::TypedSignatureKeyPair;
/// use seal_crypto_wrapper::algorithms::asymmetric::signature::SignatureAlgorithm;
///
/// // Generate a new key pair
/// let algorithm = SignatureAlgorithm::build().ed25519();
/// let keypair = TypedSignatureKeyPair::generate(algorithm)?;
///
/// // Access individual keys
/// let public_key = keypair.public_key();
/// let private_key = keypair.private_key();
///
/// // Or consume the pair to get owned keys
/// let (public_key, private_key) = keypair.into_keypair();
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, bincode::Encode, bincode::Decode)]
pub struct TypedSignatureKeyPair {
    public_key: AsymmetricPublicKey,
    private_key: AsymmetricPrivateKey,
    algorithm: SignatureAlgorithm,
}

impl TypedSignatureKeyPair {
    /// Generates a new cryptographically secure key pair for the specified signature algorithm.
    ///
    /// 为指定的签名算法生成新的密码学安全密钥对。
    ///
    /// ## Security | 安全性
    ///
    /// This method uses the operating system's cryptographically secure random
    /// number generator to create key material. The generated keys are automatically
    /// bound to the specified algorithm to prevent misuse.
    ///
    /// 此方法使用操作系统的密码学安全随机数生成器创建密钥材料。
    /// 生成的密钥自动绑定到指定算法以防止误用。
    ///
    /// ## Arguments | 参数
    ///
    /// * `algorithm` - The signature algorithm to generate keys for
    ///
    /// * `algorithm` - 要为其生成密钥的签名算法
    ///
    /// ## Returns | 返回值
    ///
    /// A new `TypedSignatureKeyPair` with both keys bound to the specified algorithm.
    ///
    /// 两个密钥都绑定到指定算法的新 `TypedSignatureKeyPair`。
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::keys::asymmetric::signature::TypedSignatureKeyPair;
    /// use seal_crypto_wrapper::algorithms::asymmetric::signature::SignatureAlgorithm;
    ///
    /// // Generate Ed25519 key pair
    /// let ed25519_pair = TypedSignatureKeyPair::generate(
    ///     SignatureAlgorithm::build().ed25519()
    /// )?;
    ///
    /// // Generate Dilithium-2 key pair
    /// let dilithium_pair = TypedSignatureKeyPair::generate(
    ///     SignatureAlgorithm::build().dilithium2()
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate(algorithm: SignatureAlgorithm) -> Result<Self, Error> {
        macro_rules! generate_keypair {
            ($key_type:ty, $alg_enum:expr) => {
                <$key_type>::generate_keypair()
                    .map_err(Error::from)
                    .and_then(|(pk, sk)| Ok(Self {
                        public_key: AsymmetricPublicKey::new(pk.to_bytes()?),
                        private_key: AsymmetricPrivateKey::new(sk.to_bytes()?),
                        algorithm: $alg_enum,
                    }))
            };
        }
        dispatch_signature!(algorithm, generate_keypair)
    }

    /// Consumes the key pair and returns the individual typed keys.
    ///
    /// 消费密钥对并返回单独的类型化密钥。
    ///
    /// This method is useful when you need to use the public and private keys
    /// separately, such as distributing the public key for signature verification
    /// while keeping the private key secure for signing operations.
    ///
    /// 当您需要单独使用公钥和私钥时，此方法很有用，
    /// 例如分发公钥用于签名验证，同时保持私钥安全用于签名操作。
    ///
    /// ## Returns | 返回值
    ///
    /// A tuple containing `(TypedSignaturePublicKey, TypedSignaturePrivateKey)`.
    ///
    /// 包含 `(TypedSignaturePublicKey, TypedSignaturePrivateKey)` 的元组。
    pub fn into_keypair(self) -> (TypedSignaturePublicKey, TypedSignaturePrivateKey) {
        (
            TypedSignaturePublicKey {
                key: self.public_key,
                algorithm: self.algorithm,
            },
            TypedSignaturePrivateKey {
                key: self.private_key,
                algorithm: self.algorithm,
            },
        )
    }

    /// Returns a copy of the public key with algorithm binding.
    ///
    /// 返回带算法绑定的公钥副本。
    ///
    /// This method allows you to access the public key without consuming
    /// the key pair, which is useful for operations like key distribution
    /// or multiple signature verification operations.
    ///
    /// 此方法允许您在不消费密钥对的情况下访问公钥，
    /// 这对密钥分发或多次签名验证操作等操作很有用。
    pub fn public_key(&self) -> TypedSignaturePublicKey {
        TypedSignaturePublicKey {
            key: self.public_key.clone(),
            algorithm: self.algorithm,
        }
    }

    /// Returns a copy of the private key with algorithm binding.
    ///
    /// 返回带算法绑定的私钥副本。
    ///
    /// ## Security Note | 安全注意
    ///
    /// This creates a copy of the private key material. Ensure proper
    /// handling and cleanup of all copies to maintain security.
    ///
    /// 这会创建私钥材料的副本。确保所有副本的正确处理和清理以保持安全性。
    pub fn private_key(&self) -> TypedSignaturePrivateKey {
        TypedSignaturePrivateKey {
            key: self.private_key.clone(),
            algorithm: self.algorithm,
        }
    }

    /// Returns the signature algorithm this key pair is bound to.
    ///
    /// 返回此密钥对绑定到的签名算法。
    ///
    /// This information is used for runtime verification to ensure the keys
    /// are only used with their intended algorithm.
    ///
    /// 此信息用于运行时验证，确保密钥仅与其预期算法一起使用。
    pub fn get_algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

/// Algorithm-bound signature public key for signature verification operations.
///
/// 用于签名验证操作的算法绑定签名公钥。
///
/// ## Purpose | 目的
///
/// This type represents a signature public key that is bound to a specific algorithm.
/// It is used for verifying digital signatures created by the corresponding private key.
/// Public keys can be safely distributed and shared for signature verification.
///
/// 此类型表示绑定到特定算法的签名公钥。
/// 它用于验证由相应私钥创建的数字签名。
/// 公钥可以安全分发和共享用于签名验证。
///
/// ## Security | 安全性
///
/// Public keys are safe to distribute and store without special protection,
/// but algorithm binding ensures they can only be used with compatible operations.
///
/// 公钥可以安全分发和存储而无需特殊保护，
/// 但算法绑定确保它们只能与兼容的操作一起使用。
///
/// ## Use Cases | 使用场景
///
/// - **Signature Verification**: Verify authenticity of signed messages
/// - **Identity Verification**: Confirm the identity of message senders
/// - **Data Integrity**: Ensure data has not been tampered with
/// - **Non-Repudiation**: Provide proof of message origin
///
/// - **签名验证**: 验证签名消息的真实性
/// - **身份验证**: 确认消息发送者的身份
/// - **数据完整性**: 确保数据未被篡改
/// - **不可否认性**: 提供消息来源证明
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, bincode::Encode, bincode::Decode)]
pub struct TypedSignaturePublicKey {
    pub(crate) key: AsymmetricPublicKey,
    pub(crate) algorithm: SignatureAlgorithm,
}

impl_typed_asymmetric_public_key!(TypedSignaturePublicKey, SignatureAlgorithm);

/// Algorithm-bound signature private key for digital signing operations.
///
/// 用于数字签名操作的算法绑定签名私钥。
///
/// ## Purpose | 目的
///
/// This type represents a signature private key that is bound to a specific algorithm.
/// It is used for creating digital signatures that can be verified by the corresponding
/// public key. Private keys must be kept secret and secure.
///
/// 此类型表示绑定到特定算法的签名私钥。
/// 它用于创建可由相应公钥验证的数字签名。
/// 私钥必须保密和安全。
///
/// ## Security | 安全性
///
/// Private keys contain sensitive material and are automatically zeroed when dropped.
/// They should be protected with appropriate access controls and secure storage.
/// Compromise of a private key allows an attacker to forge signatures.
///
/// 私钥包含敏感材料，在丢弃时自动清零。
/// 应使用适当的访问控制和安全存储来保护它们。
/// 私钥的泄露允许攻击者伪造签名。
///
/// ## Use Cases | 使用场景
///
/// - **Message Signing**: Create authenticated signatures for messages
/// - **Document Signing**: Provide legal proof of document approval
/// - **Code Signing**: Verify software authenticity and integrity
/// - **Certificate Signing**: Create digital certificates for PKI
///
/// - **消息签名**: 为消息创建认证签名
/// - **文档签名**: 提供文档批准的法律证明
/// - **代码签名**: 验证软件真实性和完整性
/// - **证书签名**: 为 PKI 创建数字证书
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, bincode::Encode, bincode::Decode)]
pub struct TypedSignaturePrivateKey {
    pub(crate) key: AsymmetricPrivateKey,
    pub(crate) algorithm: SignatureAlgorithm,
}

impl_typed_asymmetric_private_key!(TypedSignaturePrivateKey, SignatureAlgorithm);
