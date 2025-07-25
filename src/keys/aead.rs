//! Aead key types with algorithm binding and secure memory management.
//!
//! 具有算法绑定和安全内存管理的对称密钥类型。
//!
//! ## Overview | 概述
//!
//! This module provides two main types for aead key management:
//!
//! 此模块为对称密钥管理提供两种主要类型：
//!
//! - **`AeadKey`**: Untyped key material for flexible usage
//! - **`TypedAeadKey`**: Algorithm-bound keys for type-safe operations
//!
//! - **`AeadKey`**: 用于灵活使用的非类型化密钥材料
//! - **`TypedAeadKey`**: 用于类型安全操作的算法绑定密钥
//!
//! ## Key Features | 关键特性
//!
//! ### Security | 安全性
//! - Automatic memory zeroing on drop
//! - Secure random key generation
//! - Protected serialization support
//! - Constant-time operations where possible
//!
//! ### Flexibility | 灵活性
//! - Key derivation from passwords and existing keys
//! - Conversion between typed and untyped keys
//! - Support for all AEAD algorithms
//! - Serialization with algorithm preservation
//!
//! ## Usage Patterns | 使用模式
//!
//! ### Direct Key Generation | 直接密钥生成
//!
//! ```rust
//! use seal_crypto_wrapper::keys::aead::TypedAeadKey;
//! use seal_crypto_wrapper::algorithms::aead::AeadAlgorithm;
//!
//! // Generate algorithm-specific key
//! let algorithm = AeadAlgorithm::build().aes256_gcm();
//! let key = TypedAeadKey::generate(algorithm)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### Key Derivation | 密钥派生
//! ```rust
//! use seal_crypto_wrapper::keys::aead::TypedAeadKey;
//! use seal_crypto_wrapper::algorithms::kdf::key::KdfKeyAlgorithm;
//! use seal_crypto_wrapper::prelude::AeadAlgorithm;
//! #[cfg(feature = "kdf")]
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Derive key from master key
//!     let master_key = TypedAeadKey::generate(AeadAlgorithm::build().aes256_gcm())?;
//!     let kdf = KdfKeyAlgorithm::build().hkdf_sha256();
//!     let derived_key = TypedAeadKey::derive_from_kdf(
//!         &master_key.as_bytes(),
//!         kdf,
//!         Some(b"salt"),
//!         Some(b"info"),
//!         AeadAlgorithm::build().aes256_gcm()
//!     )?;
//!     Ok(())
//! }
//! ```

use crate::algorithms::aead::{AeadAlgorithm, AesKeySize};
use crate::error::Error;
#[cfg(feature = "xof")]
use crate::wrappers::xof::XofReaderWrapper;
use seal_crypto::prelude::{Key, SymmetricKeyGenerator, SymmetricKeySet};
use seal_crypto::schemes::aead::aes_gcm::{Aes128Gcm, Aes256Gcm};
use seal_crypto::schemes::aead::chacha20_poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use seal_crypto::zeroize::Zeroizing;
#[cfg(feature = "kdf")]
use {
    crate::algorithms::kdf::key::KdfKeyAlgorithm, crate::wrappers::kdf::passwd::KdfPasswordWrapper,
    seal_crypto::secrecy::SecretBox,
};

/// Macro for dispatching operations across different aead algorithms.
///
/// 用于在不同对称算法间分发操作的宏。
///
/// This internal macro provides a unified way to handle operations that need
/// to work with different concrete algorithm types while maintaining type safety.
///
/// 此内部宏提供了一种统一的方式来处理需要与不同具体算法类型一起工作
/// 同时保持类型安全的操作。
macro_rules! dispatch_aead {
    ($algorithm:expr, $action:ident) => {
        match $algorithm {
            AeadAlgorithm::AesGcm(AesKeySize::K128) => {
                $action!(Aes128Gcm, AeadAlgorithm::AesGcm(AesKeySize::K128))
            }
            AeadAlgorithm::AesGcm(AesKeySize::K256) => {
                $action!(Aes256Gcm, AeadAlgorithm::AesGcm(AesKeySize::K256))
            }
            AeadAlgorithm::XChaCha20Poly1305 => {
                $action!(XChaCha20Poly1305, AeadAlgorithm::XChaCha20Poly1305)
            }
            AeadAlgorithm::ChaCha20Poly1305 => {
                $action!(ChaCha20Poly1305, AeadAlgorithm::ChaCha20Poly1305)
            }
        }
    };
}

/// Algorithm-bound aead key with type safety guarantees.
///
/// 具有类型安全保证的算法绑定对称密钥。
///
/// ## Purpose | 目的
///
/// This type combines raw key material with algorithm metadata to prevent
/// cryptographic misuse. Once a key is bound to an algorithm, it can only
/// be used with that specific algorithm, preventing dangerous key reuse.
///
/// 此类型将原始密钥材料与算法元数据结合，以防止密码误用。
/// 一旦密钥绑定到算法，它只能与该特定算法一起使用，防止危险的密钥重用。
///
/// ## Security Properties | 安全属性
///
/// - **Algorithm Binding**: Keys are cryptographically bound to their algorithms
/// - **Memory Safety**: Automatic zeroing of sensitive data on drop
/// - **Serialization Safety**: Algorithm information is preserved during serialization
/// - **Type Safety**: Compile-time and runtime verification of algorithm compatibility
///
/// - **算法绑定**: 密钥在密码学上绑定到其算法
/// - **内存安全**: 丢弃时自动清零敏感数据
/// - **序列化安全**: 序列化期间保留算法信息
/// - **类型安全**: 算法兼容性的编译时和运行时验证
///
/// ## Examples | 示例
///
/// ```rust
/// use seal_crypto_wrapper::keys::aead::TypedAeadKey;
/// use seal_crypto_wrapper::algorithms::aead::AeadAlgorithm;
///
/// // Generate a new algorithm-bound key
/// let algorithm = AeadAlgorithm::build().aes256_gcm();
/// let key = TypedAeadKey::generate(algorithm)?;
///
/// // The key remembers its algorithm
/// assert_eq!(key.algorithm(), algorithm);
///
/// // Can be serialized with algorithm information
/// let serialized = serde_json::to_string(&key)?;
/// let deserialized: TypedAeadKey = serde_json::from_str(&serialized)?;
/// assert_eq!(deserialized.algorithm(), algorithm);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, bincode::Encode, bincode::Decode)]
pub struct TypedAeadKey {
    key: AeadKey,
    algorithm: AeadAlgorithm,
}

impl TypedAeadKey {
    /// Generates a new cryptographically secure key for the specified algorithm.
    ///
    /// 为指定算法生成新的密码学安全密钥。
    ///
    /// ## Security | 安全性
    ///
    /// This method uses the operating system's cryptographically secure random
    /// number generator to create key material with the appropriate length for
    /// the specified algorithm.
    ///
    /// 此方法使用操作系统的密码学安全随机数生成器为指定算法创建
    /// 具有适当长度的密钥材料。
    ///
    /// ## Arguments | 参数
    ///
    /// * `algorithm` - The aead algorithm to generate a key for
    ///
    /// * `algorithm` - 要为其生成密钥的对称算法
    ///
    /// ## Returns | 返回值
    ///
    /// A new `TypedAeadKey` bound to the specified algorithm.
    ///
    /// 绑定到指定算法的新 `TypedAeadKey`。
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::keys::aead::TypedAeadKey;
    /// use seal_crypto_wrapper::algorithms::aead::AeadAlgorithm;
    ///
    /// let aes_key = TypedAeadKey::generate(
    ///     AeadAlgorithm::build().aes256_gcm()
    /// )?;
    ///
    /// let chacha_key = TypedAeadKey::generate(
    ///     AeadAlgorithm::build().chacha20_poly1305()
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate(algorithm: AeadAlgorithm) -> Result<Self, Error> {
        macro_rules! generate_key {
            ($key_type:ty, $alg_enum:expr) => {
                <$key_type>::generate_key()
                    .map_err(Error::from)
                    .and_then(|k| {
                        Ok(Self {
                            key: AeadKey::new(k.to_bytes().map_err(Error::from)?),
                            algorithm: $alg_enum,
                        })
                    })
            };
        }
        dispatch_aead!(algorithm, generate_key)
    }

    /// Creates a typed key from raw bytes and algorithm specification.
    ///
    /// 从原始字节和算法规范创建类型化密钥。
    ///
    /// ## Security Warning | 安全警告
    ///
    /// This method does not validate that the provided bytes have sufficient
    /// entropy or are appropriate for cryptographic use. Only use this with
    /// bytes from trusted sources or proper key derivation functions.
    ///
    /// 此方法不验证提供的字节是否具有足够的熵或适合密码使用。
    /// 仅对来自可信源或适当密钥派生函数的字节使用此方法。
    ///
    /// ## Arguments | 参数
    ///
    /// * `bytes` - Raw key material (must match algorithm's key size)
    /// * `algorithm` - The algorithm to bind this key to
    ///
    /// * `bytes` - 原始密钥材料（必须匹配算法的密钥大小）
    /// * `algorithm` - 要将此密钥绑定到的算法
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::keys::aead::TypedAeadKey;
    /// use seal_crypto_wrapper::algorithms::aead::AeadAlgorithm;
    ///
    /// let key_bytes = [0u8; 32]; // 32 bytes for AES-256
    /// let algorithm = AeadAlgorithm::build().aes256_gcm();
    /// let key = TypedAeadKey::from_bytes(&key_bytes, algorithm)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_bytes(bytes: &[u8], algorithm: AeadAlgorithm) -> Result<Self, Error> {
        let key = AeadKey::new(bytes.to_vec());
        key.into_typed(algorithm)
    }

    /// Derives a new aead key from the current key using a specified key-based KDF.
    ///
    /// 从当前密钥派生一个新的对称密钥。
    ///
    /// This is suitable for key rotation, where a master key is used to generate
    /// sub-keys for specific purposes.
    ///
    /// 适用于密钥轮换，其中主密钥用于生成特定目的的子密钥。
    ///
    /// ## Type Parameters | 类型参数
    ///
    /// * `K` - The type of the key-based derivation algorithm, which must implement `KeyBasedDerivation`.
    ///
    /// * `K` - 密钥派生算法类型，必须实现 `KeyBasedDerivation`。
    ///
    /// ## Arguments | 参数
    ///
    /// * `deriver` - An instance of the key-based KDF scheme (e.g., `HkdfSha256`).
    /// * `salt` - An optional salt. While optional in HKDF, providing a salt is highly recommended.
    /// * `info` - Optional context-specific information.
    /// * `output_len` - The desired length of the derived key in bytes.
    ///
    /// * `deriver` - 密钥派生算法实例（例如 `HkdfSha256`）。
    /// * `salt` - 可选的盐。虽然 HKDF 中可选，但提供盐是高度推荐的。
    /// * `info` - 可选的上下文特定信息。
    /// * `output_len` - 派生密钥的期望长度（以字节为单位）。
    #[cfg(feature = "kdf")]
    pub fn derive_from_kdf(
        bytes: &[u8],
        kdf_algorithm: KdfKeyAlgorithm,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        symmetric_algorithm: AeadAlgorithm,
    ) -> Result<Self, Error> {
        use crate::traits::KdfKeyAlgorithmTrait;

        let derived_key_bytes = kdf_algorithm.into_wrapper().derive(
            bytes,
            salt,
            info,
            symmetric_algorithm.into_wrapper().key_size(),
        )?;
        Ok(TypedAeadKey::from_bytes(
            derived_key_bytes.as_slice(),
            symmetric_algorithm,
        )?)
    }

    /// Derives a aead key from a XOF reader.
    ///
    /// 从 XOF 读取器派生对称密钥。
    ///
    /// This is suitable for key rotation, where a master key is used to generate
    /// sub-keys for specific purposes.
    ///
    /// 适用于密钥轮换，其中主密钥用于生成特定目的的子密钥。
    ///
    /// ## Arguments | 参数
    ///
    /// * `xof_reader` - The XOF reader to use for derivation.
    /// * `output_len` - The desired length of the derived key in bytes.
    ///
    /// * `xof_reader` - 用于派生的 XOF 读取器。
    /// * `output_len` - 派生密钥的期望长度（以字节为单位）。
    #[cfg(feature = "xof")]
    pub fn derive_from_xof(
        xof_reader: &mut XofReaderWrapper,
        symmetric_algorithm: AeadAlgorithm,
    ) -> Result<Self, Error> {
        let mut derived_key_bytes = vec![0u8; symmetric_algorithm.into_wrapper().key_size()];
        xof_reader.read(&mut derived_key_bytes);
        Ok(TypedAeadKey::from_bytes(
            derived_key_bytes.as_slice(),
            symmetric_algorithm,
        )?)
    }

    /// Derives a aead key from a password using a specified password-based KDF.
    ///
    /// 从密码派生对称密钥。
    ///
    /// This is ideal for generating a cryptographic key from a low-entropy user password.
    /// The concrete algorithm instance (e.g., `Pbkdf2Sha256`) should be configured
    /// with the desired number of iterations before being passed to this function.
    ///
    /// ## Type Parameters | 类型参数
    ///
    /// * `P` - The type of the password-based derivation algorithm, which must implement `PasswordBasedDerivation`.
    /// * `P` - 密码派生算法类型，必须实现 `PasswordBasedDerivation`。
    ///
    /// ## Arguments | 参数
    ///
    /// * `password` - The password to derive the key from.
    /// * `deriver` - An instance of the password-based KDF scheme (e.g., `Pbkdf2Sha256::new(100_000)`).
    /// * `salt` - A salt. This is **required** for password-based derivation to be secure.
    /// * `output_len` - The desired length of the derived key in bytes.
    ///
    /// * `password` - 要派生的密码。
    /// * `deriver` - 密码派生算法实例（例如 `Pbkdf2Sha256::new(100_000)`）。
    /// * `salt` - 盐。这是 **必需** 的，因为密码派生需要安全。
    /// * `output_len` - 派生密钥的期望长度（以字节为单位）。
    #[cfg(feature = "kdf")]
    pub fn derive_from_password(
        password: &SecretBox<[u8]>,
        algorithm: KdfPasswordWrapper,
        salt: &[u8],
        symmetric_algorithm: AeadAlgorithm,
    ) -> Result<Self, Error> {
        use crate::traits::KdfPasswordAlgorithmTrait;
        let derived_key_bytes = algorithm.derive(
            password,
            salt,
            symmetric_algorithm.into_wrapper().key_size(),
        )?;
        Ok(TypedAeadKey::from_bytes(
            derived_key_bytes.as_slice(),
            symmetric_algorithm,
        )?)
    }

    /// Returns the algorithm this key is bound to.
    ///
    /// 返回此密钥绑定到的算法。
    ///
    /// This information is used for runtime verification to ensure the key
    /// is only used with its intended algorithm.
    ///
    /// 此信息用于运行时验证，确保密钥仅与其预期算法一起使用。
    pub fn algorithm(&self) -> AeadAlgorithm {
        self.algorithm
    }

    /// Converts this typed key back to an untyped key.
    ///
    /// 将此类型化密钥转换回非类型化密钥。
    ///
    /// ## Use Cases | 使用场景
    ///
    /// - Key derivation operations
    /// - Interoperability with untyped APIs
    /// - Custom key management scenarios
    ///
    /// - 密钥派生操作
    /// - 与非类型化 API 的互操作性
    /// - 自定义密钥管理场景
    ///
    /// ## Security Note | 安全注意
    ///
    /// The returned untyped key loses algorithm binding information.
    /// Use with caution to avoid algorithm misuse.
    ///
    /// 返回的非类型化密钥失去算法绑定信息。
    /// 谨慎使用以避免算法误用。
    pub fn untyped(&self) -> AeadKey {
        self.key.clone()
    }

    /// Returns a reference to the raw key bytes.
    ///
    /// 返回原始密钥字节的引用。
    ///
    /// ## Security | 安全性
    ///
    /// The returned slice provides read-only access to sensitive key material.
    /// Avoid copying or logging these bytes.
    ///
    /// 返回的切片提供对敏感密钥材料的只读访问。
    /// 避免复制或记录这些字节。
    pub fn as_bytes(&self) -> &[u8] {
        self.key.as_bytes()
    }

    /// Consumes the key and returns the raw bytes with secure cleanup.
    ///
    /// 消费密钥并返回具有安全清理的原始字节。
    ///
    /// The returned `Zeroizing<Vec<u8>>` will automatically zero its contents
    /// when dropped, providing secure cleanup of sensitive data.
    ///
    /// 返回的 `Zeroizing<Vec<u8>>` 在丢弃时会自动清零其内容，
    /// 为敏感数据提供安全清理。
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.key.into_bytes()
    }

    /// Returns a copy of the raw key bytes.
    ///
    /// 返回原始密钥字节的副本。
    ///
    /// ## Security Warning | 安全警告
    ///
    /// The returned `Vec<u8>` does not have automatic zeroing. Use `into_bytes()`
    /// or `as_bytes()` when possible to maintain better security properties.
    ///
    /// 返回的 `Vec<u8>` 没有自动清零。尽可能使用 `into_bytes()` 或 `as_bytes()`
    /// 以保持更好的安全属性。
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes()
    }
}

impl AsRef<[u8]> for TypedAeadKey {
    fn as_ref(&self) -> &[u8] {
        self.key.as_bytes()
    }
}

/// Untyped aead key for flexible cryptographic operations.
///
/// 用于灵活密码操作的非类型化对称密钥。
///
/// ## Purpose | 目的
///
/// This type stores raw key material without algorithm binding, providing
/// flexibility for key management operations such as derivation, storage,
/// and conversion to typed keys when needed.
///
/// 此类型存储没有算法绑定的原始密钥材料，为密钥管理操作提供灵活性，
/// 如派生、存储和在需要时转换为类型化密钥。
///
/// ## Use Cases | 使用场景
///
/// - **Key Derivation**: Master keys for deriving multiple sub-keys
/// - **Key Storage**: Flexible storage before algorithm selection
/// - **Key Import**: Loading keys from external sources
/// - **Key Rotation**: Managing key lifecycle operations
///
/// - **密钥派生**: 用于派生多个子密钥的主密钥
/// - **密钥存储**: 算法选择前的灵活存储
/// - **密钥导入**: 从外部源加载密钥
/// - **密钥轮换**: 管理密钥生命周期操作
///
/// ## Security Features | 安全特性
///
/// - **Automatic Zeroing**: Memory is cleared when the key is dropped
/// - **Secure Generation**: Uses OS cryptographic random number generator
/// - **Protected Serialization**: Supports secure serialization formats
/// - **Memory Safety**: Prevents accidental exposure of key material
///
/// - **自动清零**: 密钥丢弃时清除内存
/// - **安全生成**: 使用操作系统密码随机数生成器
/// - **受保护序列化**: 支持安全序列化格式
/// - **内存安全**: 防止密钥材料的意外暴露
///
/// ## Examples | 示例
///
/// ```rust
/// use seal_crypto_wrapper::keys::aead::AeadKey;
/// use seal_crypto_wrapper::algorithms::aead::AeadAlgorithm;
///
/// // Generate a random key
/// let key = AeadKey::generate(32)?;
///
/// // Convert to typed key when algorithm is known
/// let algorithm = AeadAlgorithm::build().aes256_gcm();
/// let typed_key = key.into_typed(algorithm)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ## Memory Management | 内存管理
///
/// The key material is stored in a `Zeroizing<Vec<u8>>`, which automatically
/// zeros the memory when the key is dropped, preventing sensitive data from
/// remaining in memory after use.
///
/// 密钥材料存储在 `Zeroizing<Vec<u8>>` 中，当密钥被丢弃时自动清零内存，
/// 防止敏感数据在使用后仍留在内存中。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AeadKey(pub Zeroizing<Vec<u8>>);

impl bincode::Encode for AeadKey {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> core::result::Result<(), bincode::error::EncodeError> {
        let bytes = self.0.as_slice();
        bincode::Encode::encode(bytes, encoder)?;
        Ok(())
    }
}

impl<Context> bincode::Decode<Context> for AeadKey {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> core::result::Result<Self, bincode::error::DecodeError> {
        let bytes = bincode::Decode::decode(decoder)?;
        Ok(Self(Zeroizing::new(bytes)))
    }
}

impl<'de, Context> bincode::BorrowDecode<'de, Context> for AeadKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = Context>>(
        decoder: &mut D,
    ) -> core::result::Result<Self, bincode::error::DecodeError> {
        let bytes = bincode::BorrowDecode::borrow_decode(decoder)?;
        Ok(Self(Zeroizing::new(bytes)))
    }
}

impl AeadKey {
    /// Create a new aead key from bytes
    ///
    /// 从字节创建一个新的对称密钥
    pub fn new(bytes: impl Into<Zeroizing<Vec<u8>>>) -> Self {
        Self(bytes.into())
    }

    /// Generates a new random aead key of the specified length.
    ///
    /// This is useful for creating new keys for encryption or for key rotation.
    /// It uses the operating system's cryptographically secure random number generator.
    ///
    /// 生成一个指定长度的新的随机对称密钥。
    ///
    /// 这对于为加密或密钥轮换创建新密钥很有用。
    /// 它使用操作系统的加密安全随机数生成器。
    ///
    /// # Arguments
    ///
    /// * `len` - The desired length of the key in bytes.
    ///
    /// * `len` - 所需的密钥长度（以字节为单位）。
    pub fn generate(len: usize) -> Result<Self, Error> {
        use rand::{TryRngCore, rngs::OsRng};
        let mut key_bytes = vec![0; len];
        OsRng.try_fill_bytes(&mut key_bytes)?;
        Ok(Self::new(key_bytes))
    }

    /// Get a reference to the raw bytes of the key
    ///
    /// 获取密钥原始字节的引用
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Consume the key and return the inner bytes
    ///
    /// 消耗密钥并返回内部字节
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.0
    }

    /// Converts the raw key bytes into a typed aead key enum.
    ///
    /// 将原始密钥字节转换为类型化的对称密钥枚举。
    pub fn into_typed(self, algorithm: AeadAlgorithm) -> Result<TypedAeadKey, Error> {
        macro_rules! into_typed_key {
            ($key_type:ty, $alg_enum:expr) => {{
                let key = <$key_type as SymmetricKeySet>::Key::from_bytes(self.as_bytes())?;
                Ok(TypedAeadKey {
                    key: AeadKey::new(key.to_bytes().map_err(Error::from)?),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_aead!(algorithm, into_typed_key)
    }
}
