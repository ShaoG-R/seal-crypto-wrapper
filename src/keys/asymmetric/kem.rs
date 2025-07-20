//! Key Encapsulation Mechanism (KEM) key types and operations.
//!
//! 密钥封装机制 (KEM) 密钥类型和操作。
//!
//! ## Overview | 概述
//!
//! This module provides type-safe key management for Key Encapsulation Mechanisms,
//! which are used to securely establish shared secrets between parties. KEM is
//! particularly important for post-quantum cryptography and hybrid encryption schemes.
//!
//! 此模块为密钥封装机制提供类型安全的密钥管理，
//! 用于在各方之间安全建立共享密钥。KEM 对后量子密码学和混合加密方案特别重要。
//!
//! ## KEM Operations | KEM 操作
//!
//! ### Key Generation | 密钥生成
//! Generate a public-private key pair for the KEM algorithm.
//!
//! 为 KEM 算法生成公私钥对。
//!
//! ### Encapsulation | 封装
//! Use the public key to generate a shared secret and its encapsulated form.
//!
//! 使用公钥生成共享密钥及其封装形式。
//!
//! ### Decapsulation | 解封装
//! Use the private key to recover the shared secret from the encapsulated key.
//!
//! 使用私钥从封装密钥中恢复共享密钥。
//!
//! ## Supported Algorithms | 支持的算法
//!
//! - **RSA KEM**: Traditional public-key cryptosystem (2048/4096-bit)
//! - **Kyber**: Post-quantum lattice-based KEM (512/768/1024 security levels)
//!
//! ## Security Considerations | 安全考虑
//!
//! - **Shared Secret Protection**: Shared secrets are stored in `Zeroizing` containers
//! - **Algorithm Binding**: Keys are bound to specific algorithms to prevent misuse
//! - **Post-Quantum Security**: Kyber algorithms provide quantum-resistant security
//!
//! - **共享密钥保护**: 共享密钥存储在 `Zeroizing` 容器中
//! - **算法绑定**: 密钥绑定到特定算法以防止误用
//! - **后量子安全**: Kyber 算法提供抗量子安全性
//!
//! ## Examples | 示例
//!
//! ```rust
//! use seal_crypto_wrapper::algorithms::asymmetric::AsymmetricAlgorithm;
//!
//! // Generate KEM key pair
//! let algorithm = AsymmetricAlgorithm::build().kem().kyber512();
//! let kem = algorithm.into_asymmetric_wrapper();
//! let keypair = kem.generate_keypair()?;
//!
//! // Separate keys
//! let (public_key, private_key) = keypair.into_keypair();
//!
//! // Encapsulate shared secret
//! let (shared_secret, ciphertext) = kem.encapsulate_key(&public_key)?;
//!
//! // Decapsulate to recover shared secret
//! let recovered_secret = kem.decapsulate_key(&private_key, &ciphertext)?;
//! assert_eq!(shared_secret, recovered_secret);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::algorithms::asymmetric::kem::KemAlgorithm;
use crate::dispatch_kem;
use crate::error::Error;
use crate::impl_typed_asymmetric_private_key;
use crate::impl_typed_asymmetric_public_key;
use crate::keys::asymmetric::TypedAsymmetricKeyTrait;
use crate::keys::asymmetric::{AsymmetricPrivateKey, AsymmetricPublicKey};
use seal_crypto::prelude::{Key, KeyGenerator};
use seal_crypto::zeroize::Zeroizing;

#[cfg(all(feature = "kdf", feature = "symmetric"))]
use crate::{
    prelude::{SymmetricAlgorithm, TypedSymmetricKey},
    algorithms::kdf::key::KdfKeyAlgorithm
};

#[cfg(all(feature = "xof", feature = "symmetric"))]
use crate::wrappers::xof::XofReaderWrapper;

/// Algorithm-bound KEM key pair for secure key encapsulation operations.
///
/// 用于安全密钥封装操作的算法绑定 KEM 密钥对。
///
/// ## Purpose | 目的
///
/// This type represents a complete KEM key pair (public and private keys) that is
/// bound to a specific KEM algorithm. It ensures that both keys can only be used
/// with the algorithm they were generated for, preventing cryptographic misuse.
///
/// 此类型表示绑定到特定 KEM 算法的完整 KEM 密钥对（公钥和私钥）。
/// 它确保两个密钥只能与生成它们的算法一起使用，防止密码误用。
///
/// ## Key Features | 关键特性
///
/// - **Algorithm Binding**: Both keys are bound to the same KEM algorithm
/// - **Type Safety**: Prevents using keys with incompatible algorithms
/// - **Serialization**: Supports secure serialization with algorithm metadata
/// - **Memory Safety**: Private key material is automatically zeroed on drop
///
/// - **算法绑定**: 两个密钥都绑定到相同的 KEM 算法
/// - **类型安全**: 防止将密钥与不兼容的算法一起使用
/// - **序列化**: 支持带算法元数据的安全序列化
/// - **内存安全**: 私钥材料在丢弃时自动清零
///
/// ## Usage Pattern | 使用模式
///
/// ```rust
/// use seal_crypto_wrapper::keys::asymmetric::kem::TypedKemKeyPair;
/// use seal_crypto_wrapper::algorithms::asymmetric::kem::KemAlgorithm;
///
/// // Generate a new key pair
/// let algorithm = KemAlgorithm::build().kyber512();
/// let keypair = TypedKemKeyPair::generate(algorithm)?;
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
pub struct TypedKemKeyPair {
    pub(crate) public_key: AsymmetricPublicKey,
    pub(crate) private_key: AsymmetricPrivateKey,
    pub(crate) algorithm: KemAlgorithm,
}

impl TypedKemKeyPair {
    /// Generates a new cryptographically secure key pair for the specified KEM algorithm.
    ///
    /// 为指定的 KEM 算法生成新的密码学安全密钥对。
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
    /// * `algorithm` - The KEM algorithm to generate keys for
    ///
    /// * `algorithm` - 要为其生成密钥的 KEM 算法
    ///
    /// ## Returns | 返回值
    ///
    /// A new `TypedKemKeyPair` with both keys bound to the specified algorithm.
    ///
    /// 两个密钥都绑定到指定算法的新 `TypedKemKeyPair`。
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::keys::asymmetric::kem::TypedKemKeyPair;
    /// use seal_crypto_wrapper::algorithms::asymmetric::kem::KemAlgorithm;
    ///
    /// // Generate Kyber-512 key pair
    /// let kyber_pair = TypedKemKeyPair::generate(
    ///     KemAlgorithm::build().kyber512()
    /// )?;
    ///
    /// // Generate RSA-2048 key pair
    /// let rsa_pair = TypedKemKeyPair::generate(
    ///     KemAlgorithm::build().rsa2048().sha256()
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate(algorithm: KemAlgorithm) -> Result<Self, Error> {
        macro_rules! generate_keypair {
            ($key_type:ty, $alg_enum:expr) => {
                <$key_type>::generate_keypair()
                    .map(|(pk, sk)| Self {
                        public_key: AsymmetricPublicKey::new(pk.to_bytes()),
                        private_key: AsymmetricPrivateKey::new(sk.to_bytes()),
                        algorithm: $alg_enum,
                    })
                    .map_err(Error::from)
            };
        }
        dispatch_kem!(algorithm, generate_keypair)
    }

    /// Consumes the key pair and returns the individual typed keys.
    ///
    /// 消费密钥对并返回单独的类型化密钥。
    ///
    /// This method is useful when you need to use the public and private keys
    /// separately, such as distributing the public key while keeping the
    /// private key secure.
    ///
    /// 当您需要单独使用公钥和私钥时，此方法很有用，
    /// 例如分发公钥同时保持私钥安全。
    ///
    /// ## Returns | 返回值
    ///
    /// A tuple containing `(TypedKemPublicKey, TypedKemPrivateKey)`.
    ///
    /// 包含 `(TypedKemPublicKey, TypedKemPrivateKey)` 的元组。
    pub fn into_keypair(self) -> (TypedKemPublicKey, TypedKemPrivateKey) {
        (
            TypedKemPublicKey {
                key: self.public_key,
                algorithm: self.algorithm,
            },
            TypedKemPrivateKey {
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
    /// or multiple encapsulation operations.
    ///
    /// 此方法允许您在不消费密钥对的情况下访问公钥，
    /// 这对密钥分发或多次封装操作等操作很有用。
    pub fn public_key(&self) -> TypedKemPublicKey {
        TypedKemPublicKey {
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
    pub fn private_key(&self) -> TypedKemPrivateKey {
        TypedKemPrivateKey {
            key: self.private_key.clone(),
            algorithm: self.algorithm,
        }
    }

    /// Returns the KEM algorithm this key pair is bound to.
    ///
    /// 返回此密钥对绑定到的 KEM 算法。
    ///
    /// This information is used for runtime verification to ensure the keys
    /// are only used with their intended algorithm.
    ///
    /// 此信息用于运行时验证，确保密钥仅与其预期算法一起使用。
    pub fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }
}

/// Algorithm-bound KEM public key for key encapsulation operations.
///
/// 用于密钥封装操作的算法绑定 KEM 公钥。
///
/// ## Purpose | 目的
///
/// This type represents a KEM public key that is bound to a specific algorithm.
/// It is used for encapsulating shared secrets that can only be decapsulated
/// by the corresponding private key.
///
/// 此类型表示绑定到特定算法的 KEM 公钥。
/// 它用于封装只能由相应私钥解封装的共享密钥。
///
/// ## Security | 安全性
///
/// Public keys are safe to distribute and store without special protection,
/// but algorithm binding ensures they can only be used with compatible operations.
///
/// 公钥可以安全分发和存储而无需特殊保护，
/// 但算法绑定确保它们只能与兼容的操作一起使用。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, bincode::Encode, bincode::Decode)]
pub struct TypedKemPublicKey {
    pub(crate) key: AsymmetricPublicKey,
    pub(crate) algorithm: KemAlgorithm,
}

impl_typed_asymmetric_public_key!(TypedKemPublicKey, KemAlgorithm);

/// Algorithm-bound KEM private key for key decapsulation operations.
///
/// 用于密钥解封装操作的算法绑定 KEM 私钥。
///
/// ## Purpose | 目的
///
/// This type represents a KEM private key that is bound to a specific algorithm.
/// It is used for decapsulating shared secrets from encapsulated keys created
/// with the corresponding public key.
///
/// 此类型表示绑定到特定算法的 KEM 私钥。
/// 它用于从使用相应公钥创建的封装密钥中解封装共享密钥。
///
/// ## Security | 安全性
///
/// Private keys contain sensitive material and are automatically zeroed when dropped.
/// They should be protected with appropriate access controls and secure storage.
///
/// 私钥包含敏感材料，在丢弃时自动清零。
/// 应使用适当的访问控制和安全存储来保护它们。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, bincode::Encode, bincode::Decode)]
pub struct TypedKemPrivateKey {
    pub(crate) key: AsymmetricPrivateKey,
    pub(crate) algorithm: KemAlgorithm,
}

impl_typed_asymmetric_private_key!(TypedKemPrivateKey, KemAlgorithm);

/// Shared secret generated by KEM operations with automatic memory cleanup.
///
/// 由 KEM 操作生成的具有自动内存清理的共享密钥。
///
/// ## Purpose | 目的
///
/// This type holds the shared secret material generated during KEM encapsulation
/// or recovered during decapsulation. The secret is automatically zeroed when
/// the value is dropped to prevent sensitive data from remaining in memory.
///
/// 此类型保存在 KEM 封装期间生成或在解封装期间恢复的共享密钥材料。
/// 当值被丢弃时，密钥会自动清零，以防止敏感数据留在内存中。
///
/// ## Security | 安全性
///
/// The shared secret should be used immediately for key derivation or encryption
/// and not stored for extended periods. Use appropriate key derivation functions
/// to derive actual encryption keys from this material.
///
/// 共享密钥应立即用于密钥派生或加密，不应长期存储。
/// 使用适当的密钥派生函数从此材料派生实际的加密密钥。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedSecret(pub Zeroizing<Vec<u8>>);

impl SharedSecret {
    /// Derives a symmetric key from the shared secret using a KDF algorithm.
    ///
    /// 使用 KDF 算法从共享密钥派生对称密钥。
    ///
    /// This method derives a symmetric key from the shared secret using a KDF algorithm.
    /// The derived key is returned as a `TypedSymmetricKey` object.
    ///
    /// 此方法使用 KDF 算法从共享密钥派生对称密钥。派生的密钥作为 `TypedSymmetricKey` 对象返回。
    #[cfg(all(feature = "kdf", feature = "symmetric"))]
    pub fn derive_key(
        &self,
        kdf_algorithm: KdfKeyAlgorithm,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        algorithm: SymmetricAlgorithm,
    ) -> Result<TypedSymmetricKey, Error> {
        use crate::traits::KdfKeyAlgorithmTrait;

        let derived_key_bytes = kdf_algorithm.into_kdf_key_wrapper().derive(
            self.0.as_ref(),
            salt,
            info,
            algorithm.into_symmetric_wrapper().key_size(),
        )?;
        TypedSymmetricKey::from_bytes(derived_key_bytes.as_slice(), algorithm)
    }

    /// Derives a symmetric key from the shared secret using a XOF algorithm.
    ///
    /// 使用 XOF 算法从共享密钥派生对称密钥。
    ///
    /// This method derives a symmetric key from the shared secret using a XOF algorithm.
    /// The derived key is returned as a `TypedSymmetricKey` object.
    ///
    /// 此方法使用 XOF 算法从共享密钥派生对称密钥。派生的密钥作为 `TypedSymmetricKey` 对象返回。
    #[cfg(all(feature = "xof", feature = "symmetric"))]
    pub fn derive_key_from_xof(
        &self,
        xof_reader: &mut XofReaderWrapper,
        algorithm: SymmetricAlgorithm,
    ) -> Result<TypedSymmetricKey, Error> {
        let mut derived_key_bytes = vec![0u8; algorithm.into_symmetric_wrapper().key_size()];
        xof_reader.read(&mut derived_key_bytes);

        TypedSymmetricKey::from_bytes(derived_key_bytes.as_slice(), algorithm)
    }

    /// Consumes the shared secret and returns the raw bytes.
    ///
    /// 消费共享密钥并返回原始字节。
    ///
    /// This method takes ownership of the shared secret and returns
    /// the underlying byte vector. Use this when you need to move the
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.0
    }

    /// Returns a reference to the shared secret bytes.
    ///
    /// 返回共享密钥字节的引用。
    ///
    /// This method provides read-only access to the shared secret data without copying.
    /// Prefer this over `into_bytes()` when you only need to read the data.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Returns a copy of the shared secret bytes.
    ///
    /// 返回共享密钥字节的副本。
    ///
    /// This method creates a new vector containing the shared secret data.
    /// Use this when you need an owned copy of the shared secret.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl std::ops::Deref for SharedSecret {
    type Target = Zeroizing<Vec<u8>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Algorithm-bound encapsulated key for KEM operations.
///
/// 用于 KEM 操作的算法绑定封装密钥。
///
/// ## Purpose | 目的
///
/// This type represents the encapsulated form of a shared secret, created during
/// KEM encapsulation. It can be safely transmitted or stored and later used with
/// the corresponding private key to recover the shared secret.
///
/// 此类型表示在 KEM 封装期间创建的共享密钥的封装形式。
/// 它可以安全传输或存储，稍后与相应的私钥一起使用以恢复共享密钥。
///
/// ## Security | 安全性
///
/// Encapsulated keys are safe to transmit over insecure channels as they do not
/// reveal the underlying shared secret without the corresponding private key.
///
/// 封装密钥可以安全地通过不安全通道传输，因为没有相应的私钥它们不会泄露底层共享密钥。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, bincode::Encode, bincode::Decode)]
pub struct EncapsulatedKey {
    pub(crate) key: Vec<u8>,
    pub(crate) algorithm: KemAlgorithm,
}

impl EncapsulatedKey {
    /// Returns a copy of the encapsulated key bytes.
    ///
    /// 返回封装密钥字节的副本。
    ///
    /// This method creates a new vector containing the encapsulated key data.
    /// Use this when you need an owned copy of the key material.
    ///
    /// 此方法创建包含封装密钥数据的新向量。
    /// 当您需要密钥材料的拥有副本时使用此方法。
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.clone()
    }

    /// Returns a reference to the encapsulated key bytes.
    ///
    /// 返回封装密钥字节的引用。
    ///
    /// This method provides read-only access to the key data without copying.
    /// Prefer this over `to_bytes()` when you only need to read the data.
    ///
    /// 此方法提供对密钥数据的只读访问而不复制。
    /// 当您只需要读取数据时，优先使用此方法而不是 `to_bytes()`。
    pub fn as_bytes(&self) -> &[u8] {
        self.key.as_ref()
    }

    /// Consumes the encapsulated key and returns the raw bytes.
    ///
    /// 消费封装密钥并返回原始字节。
    ///
    /// This method takes ownership of the encapsulated key and returns
    /// the underlying byte vector. Use this when you need to move the
    /// key data without copying.
    ///
    /// 此方法获取封装密钥的所有权并返回底层字节向量。
    /// 当您需要移动密钥数据而不复制时使用此方法。
    pub fn into_bytes(self) -> Vec<u8> {
        self.key
    }
}

impl AsRef<[u8]> for EncapsulatedKey {
    fn as_ref(&self) -> &[u8] {
        self.key.as_ref()
    }
}

impl TypedAsymmetricKeyTrait for EncapsulatedKey {
    type Algorithm = KemAlgorithm;

    fn algorithm(&self) -> Self::Algorithm {
        self.algorithm
    }
}
