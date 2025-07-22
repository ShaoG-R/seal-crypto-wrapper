//! Key agreement protocol key types and operations.
//!
//! 密钥协商协议密钥类型和操作。
//!
//! ## Overview | 概述
//!
//! This module provides type-safe key management for key agreement protocols,
//! which allow two or more parties to establish a shared secret over an insecure
//! communication channel. The shared secret can then be used for aead encryption
//! or other cryptographic operations.
//!
//! 此模块为密钥协商协议提供类型安全的密钥管理，
//! 允许两方或多方通过不安全的通信通道建立共享密钥。
//! 然后可以将共享密钥用于对称加密或其他密码操作。
//!
//! ## Key Agreement Operations | 密钥协商操作
//!
//! ### Key Generation | 密钥生成
//! Each party generates their own public-private key pair.
//!
//! 每一方生成自己的公私钥对。
//!
//! ### Key Exchange | 密钥交换
//! Parties exchange their public keys over the communication channel.
//!
//! 各方通过通信通道交换其公钥。
//!
//! ### Shared Secret Derivation | 共享密钥派生
//! Each party uses their private key and the other party's public key to derive the same shared secret.
//!
//! 每一方使用其私钥和对方的公钥派生相同的共享密钥。
//!
//! ## Supported Algorithms | 支持的算法
//!
//! - **ECDH P-256**: Elliptic Curve Diffie-Hellman over NIST P-256 curve
//!   - Provides 128-bit security level
//!   - Widely supported and standardized
//!   - Efficient implementation
//!
//! ## Security Considerations | 安全考虑
//!
//! - **Forward Secrecy**: Use ephemeral keys for forward secrecy
//! - **Authentication**: Key agreement alone doesn't provide authentication
//! - **Man-in-the-Middle**: Combine with authentication to prevent MITM attacks
//! - **Key Derivation**: Use proper KDF to derive actual encryption keys
//!
//! - **前向保密**: 使用临时密钥实现前向保密
//! - **认证**: 密钥协商本身不提供认证
//! - **中间人攻击**: 结合认证防止中间人攻击
//! - **密钥派生**: 使用适当的 KDF 派生实际的加密密钥
//!
//! ## Examples | 示例
//!
//! ```rust
//! use seal_crypto_wrapper::algorithms::asymmetric::AsymmetricAlgorithm;
//!
//! // Alice generates her key pair
//! let algorithm = AsymmetricAlgorithm::build().key_agreement().ecdh_p256();
//! let ka = algorithm.into_wrapper();
//! let alice_keypair = ka.generate_keypair()?;
//! let (alice_public, alice_private) = alice_keypair.into_keypair();
//!
//! // Bob generates his key pair
//! let bob_keypair = ka.generate_keypair()?;
//! let (bob_public, bob_private) = bob_keypair.into_keypair();
//!
//! // Both parties derive the same shared secret
//! let alice_shared = ka.agree(&alice_private, &bob_public)?;
//! let bob_shared = ka.agree(&bob_private, &alice_public)?;
//! assert_eq!(alice_shared, bob_shared);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;
use crate::dispatch_key_agreement;
use crate::error::Error;
use crate::impl_typed_asymmetric_private_key;
use crate::impl_typed_asymmetric_public_key;
use crate::keys::asymmetric::{AsymmetricPrivateKey, AsymmetricPublicKey};
use seal_crypto::prelude::{Key, KeyGenerator};

/// Algorithm-bound key agreement key pair for shared secret establishment.
///
/// 用于共享密钥建立的算法绑定密钥协商密钥对。
///
/// ## Purpose | 目的
///
/// This type represents a complete key agreement key pair (public and private keys) that is
/// bound to a specific key agreement algorithm. It ensures that both keys can only be used
/// with the algorithm they were generated for, preventing cryptographic misuse.
///
/// 此类型表示绑定到特定密钥协商算法的完整密钥协商密钥对（公钥和私钥）。
/// 它确保两个密钥只能与生成它们的算法一起使用，防止密码误用。
///
/// ## Key Features | 关键特性
///
/// - **Algorithm Binding**: Both keys are bound to the same key agreement algorithm
/// - **Type Safety**: Prevents using keys with incompatible algorithms
/// - **Serialization**: Supports secure serialization with algorithm metadata
/// - **Memory Safety**: Private key material is automatically zeroed on drop
///
/// - **算法绑定**: 两个密钥都绑定到相同的密钥协商算法
/// - **类型安全**: 防止将密钥与不兼容的算法一起使用
/// - **序列化**: 支持带算法元数据的安全序列化
/// - **内存安全**: 私钥材料在丢弃时自动清零
///
/// ## Usage Pattern | 使用模式
///
/// ```rust
/// use seal_crypto_wrapper::keys::asymmetric::key_agreement::TypedKeyAgreementKeyPair;
/// use seal_crypto_wrapper::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;
///
/// // Generate a new key pair
/// let algorithm = KeyAgreementAlgorithm::build().ecdh_p256();
/// let keypair = TypedKeyAgreementKeyPair::generate(algorithm)?;
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
pub struct TypedKeyAgreementKeyPair {
    public_key: TypedKeyAgreementPublicKey,
    private_key: TypedKeyAgreementPrivateKey,
}

impl TypedKeyAgreementKeyPair {
    /// Generates a new cryptographically secure key pair for the specified key agreement algorithm.
    ///
    /// 为指定的密钥协商算法生成新的密码学安全密钥对。
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
    /// * `algorithm` - The key agreement algorithm to generate keys for
    ///
    /// * `algorithm` - 要为其生成密钥的密钥协商算法
    ///
    /// ## Returns | 返回值
    ///
    /// A new `TypedKeyAgreementKeyPair` with both keys bound to the specified algorithm.
    ///
    /// 两个密钥都绑定到指定算法的新 `TypedKeyAgreementKeyPair`。
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::keys::asymmetric::key_agreement::TypedKeyAgreementKeyPair;
    /// use seal_crypto_wrapper::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;
    ///
    /// // Generate ECDH P-256 key pair
    /// let ecdh_pair = TypedKeyAgreementKeyPair::generate(
    ///     KeyAgreementAlgorithm::build().ecdh_p256()
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate(algorithm: KeyAgreementAlgorithm) -> Result<Self, Error> {
        macro_rules! generate_keypair {
            ($key_type:ty, $alg_enum:expr) => {
                <$key_type>::generate_keypair()
                    .map_err(Error::from)
                    .and_then(|(pk, sk)| Ok(Self {
                        public_key: TypedKeyAgreementPublicKey {
                            key: AsymmetricPublicKey::new(pk.to_bytes()?),
                            algorithm: $alg_enum,
                        },
                        private_key: TypedKeyAgreementPrivateKey {
                            key: AsymmetricPrivateKey::new(sk.to_bytes()?),
                            algorithm: $alg_enum,
                        },
                    }))
            };
        }
        dispatch_key_agreement!(algorithm, generate_keypair)
    }

    /// Consumes the key pair and returns the individual typed keys.
    ///
    /// 消费密钥对并返回单独的类型化密钥。
    ///
    /// This method is useful when you need to use the public and private keys
    /// separately, such as sharing the public key with other parties while
    /// keeping the private key secure for key agreement operations.
    ///
    /// 当您需要单独使用公钥和私钥时，此方法很有用，
    /// 例如与其他方共享公钥，同时保持私钥安全用于密钥协商操作。
    ///
    /// ## Returns | 返回值
    ///
    /// A tuple containing `(TypedKeyAgreementPublicKey, TypedKeyAgreementPrivateKey)`.
    ///
    /// 包含 `(TypedKeyAgreementPublicKey, TypedKeyAgreementPrivateKey)` 的元组。
    pub fn into_keypair(self) -> (TypedKeyAgreementPublicKey, TypedKeyAgreementPrivateKey) {
        (
            self.public_key,
            self.private_key,
        )
    }

    /// Returns a copy of the public key with algorithm binding.
    ///
    /// 返回带算法绑定的公钥副本。
    ///
    /// This method allows you to access the public key without consuming
    /// the key pair, which is useful for operations like key distribution
    /// or multiple key agreement operations with different parties.
    ///
    /// 此方法允许您在不消费密钥对的情况下访问公钥，
    /// 这对密钥分发或与不同方的多次密钥协商操作等操作很有用。
    pub fn public_key(&self) -> &TypedKeyAgreementPublicKey {
        &self.public_key
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
    pub fn private_key(&self) -> &TypedKeyAgreementPrivateKey {
        &self.private_key
    }

    /// Returns the key agreement algorithm this key pair is bound to.
    ///
    /// 返回此密钥对绑定到的密钥协商算法。
    ///
    /// This information is used for runtime verification to ensure the keys
    /// are only used with their intended algorithm.
    ///
    /// 此信息用于运行时验证，确保密钥仅与其预期算法一起使用。
    pub fn get_algorithm(&self) -> KeyAgreementAlgorithm {
        self.public_key.algorithm
    }
}

/// Algorithm-bound key agreement public key for shared secret establishment.
///
/// 用于共享密钥建立的算法绑定密钥协商公钥。
///
/// ## Purpose | 目的
///
/// This type represents a key agreement public key that is bound to a specific algorithm.
/// It is used in key agreement protocols where parties exchange public keys to establish
/// a shared secret. Public keys can be safely distributed and shared.
///
/// 此类型表示绑定到特定算法的密钥协商公钥。
/// 它用于密钥协商协议，各方交换公钥以建立共享密钥。
/// 公钥可以安全分发和共享。
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
/// - **Key Exchange**: Share with other parties for key agreement
/// - **Ephemeral Keys**: Use for forward secrecy in protocols
/// - **Static Keys**: Use for long-term key agreement relationships
/// - **Hybrid Protocols**: Combine with other cryptographic primitives
///
/// - **密钥交换**: 与其他方共享用于密钥协商
/// - **临时密钥**: 用于协议中的前向保密
/// - **静态密钥**: 用于长期密钥协商关系
/// - **混合协议**: 与其他密码原语结合
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, bincode::Encode, bincode::Decode)]
pub struct TypedKeyAgreementPublicKey {
    pub(crate) key: AsymmetricPublicKey,
    pub(crate) algorithm: KeyAgreementAlgorithm,
}

impl_typed_asymmetric_public_key!(TypedKeyAgreementPublicKey, KeyAgreementAlgorithm);

/// Algorithm-bound key agreement private key for shared secret derivation.
///
/// 用于共享密钥派生的算法绑定密钥协商私钥。
///
/// ## Purpose | 目的
///
/// This type represents a key agreement private key that is bound to a specific algorithm.
/// It is used to derive shared secrets from other parties' public keys in key agreement
/// protocols. Private keys must be kept secret and secure.
///
/// 此类型表示绑定到特定算法的密钥协商私钥。
/// 它用于在密钥协商协议中从其他方的公钥派生共享密钥。
/// 私钥必须保密和安全。
///
/// ## Security | 安全性
///
/// Private keys contain sensitive material and are automatically zeroed when dropped.
/// They should be protected with appropriate access controls and secure storage.
/// Compromise of a private key allows an attacker to derive shared secrets.
///
/// 私钥包含敏感材料，在丢弃时自动清零。
/// 应使用适当的访问控制和安全存储来保护它们。
/// 私钥的泄露允许攻击者派生共享密钥。
///
/// ## Use Cases | 使用场景
///
/// - **Shared Secret Derivation**: Combine with others' public keys
/// - **Forward Secrecy**: Use ephemeral keys for each session
/// - **Perfect Forward Secrecy**: Delete after use to prevent future compromise
/// - **Key Derivation**: Use derived secrets for aead encryption
///
/// - **共享密钥派生**: 与他人的公钥结合
/// - **前向保密**: 为每个会话使用临时密钥
/// - **完美前向保密**: 使用后删除以防止未来泄露
/// - **密钥派生**: 使用派生的密钥进行对称加密
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, bincode::Encode, bincode::Decode)]
pub struct TypedKeyAgreementPrivateKey {
    pub(crate) key: AsymmetricPrivateKey,
    pub(crate) algorithm: KeyAgreementAlgorithm,
}

impl_typed_asymmetric_private_key!(TypedKeyAgreementPrivateKey, KeyAgreementAlgorithm);
