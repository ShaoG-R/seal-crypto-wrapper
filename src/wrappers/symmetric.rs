//! Symmetric encryption algorithm wrappers with AEAD support.
//!
//! 支持 AEAD 的对称加密算法包装器。
//!
//! ## Overview | 概述
//!
//! This module provides concrete implementations of symmetric encryption algorithms
//! that support Authenticated Encryption with Associated Data (AEAD). Each wrapper
//! implements the `SymmetricAlgorithmTrait` and provides type-safe access to the
//! underlying cryptographic operations.
//!
//! 此模块提供支持带关联数据认证加密 (AEAD) 的对称加密算法的具体实现。
//! 每个包装器都实现 `SymmetricAlgorithmTrait` 并提供对底层密码操作的类型安全访问。
//!
//! ## Supported Algorithms | 支持的算法
//!
//! - **AES-128-GCM**: Fast, hardware-accelerated, 128-bit security
//! - **AES-256-GCM**: Fast, hardware-accelerated, 256-bit security
//! - **ChaCha20-Poly1305**: Software-optimized, 256-bit security
//! - **XChaCha20-Poly1305**: Extended nonce variant, 256-bit security
//!
//! ## Key Features | 关键特性
//!
//! ### Type Safety | 类型安全
//! - Algorithm-key binding verification
//! - Runtime compatibility checking
//! - Compile-time algorithm selection
//!
//! ### Performance | 性能
//! - Zero-allocation buffer operations
//! - Hardware acceleration when available
//! - Optimized software implementations
//!
//! ### Security | 安全性
//! - Authenticated encryption (confidentiality + integrity)
//! - Associated data authentication
//! - Constant-time operations
//! - Secure memory management
//!
//! ## Usage Examples | 使用示例
//!
//! ### Basic Encryption | 基本加密
//!
//! ```rust
//! use seal_crypto_wrapper::algorithms::symmetric::SymmetricAlgorithm;
//!
//! let algorithm = SymmetricAlgorithm::build().aes256_gcm();
//! let cipher = algorithm.into_symmetric_wrapper();
//! let key = cipher.generate_typed_key()?;
//!
//! let plaintext = b"Hello, World!";
//! let nonce = vec![0u8; cipher.nonce_size()]; // Use random nonce in production
//! let ciphertext = cipher.encrypt(plaintext, &key, &nonce, None)?;
//!
//! let decrypted = cipher.decrypt(&ciphertext, &key, &nonce, None)?;
//! assert_eq!(plaintext, &decrypted[..]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### With Associated Data | 使用关联数据
//!
//! ```rust
//! use seal_crypto_wrapper::algorithms::symmetric::SymmetricAlgorithm;
//!
//! let cipher = SymmetricAlgorithm::build().chacha20_poly1305().into_symmetric_wrapper();
//! let key = cipher.generate_typed_key()?;
//!
//! let plaintext = b"Secret message";
//! let aad = b"public header";
//! let nonce = vec![0u8; cipher.nonce_size()];
//!
//! let ciphertext = cipher.encrypt(plaintext, &key, &nonce, Some(aad))?;
//! let decrypted = cipher.decrypt(&ciphertext, &key, &nonce, Some(aad))?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::algorithms::symmetric::{AesKeySize, SymmetricAlgorithm};
use crate::error::{Error, FormatError, Result};
use crate::keys::symmetric::{SymmetricKey as UntypedSymmetricKey, TypedSymmetricKey};
use crate::traits::SymmetricAlgorithmTrait;
use rand::TryRngCore;
use rand::rngs::OsRng;
use seal_crypto::prelude::{Key, SymmetricCipher, SymmetricDecryptor, SymmetricEncryptor};
use seal_crypto::schemes::symmetric::aes_gcm::{Aes128Gcm, Aes256Gcm};
use seal_crypto::schemes::symmetric::chacha20_poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use std::ops::Deref;

/// Macro for implementing symmetric algorithm wrappers.
///
/// 用于实现对称算法包装器的宏。
///
/// This macro generates a complete wrapper implementation for a symmetric algorithm,
/// including all required trait methods, key validation, and error handling.
///
/// 此宏为对称算法生成完整的包装器实现，
/// 包括所有必需的 trait 方法、密钥验证和错误处理。
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
macro_rules! impl_symmetric_algorithm {
    ($wrapper:ident, $algo:ty, $algo_enum:expr) => {
        /// Wrapper implementation for a specific symmetric algorithm.
        ///
        /// 特定对称算法的包装器实现。
        ///
        /// This struct provides a type-safe interface to the underlying cryptographic
        /// algorithm, ensuring that keys are validated and operations are performed
        /// with the correct algorithm parameters.
        ///
        /// 此结构体为底层密码算法提供类型安全接口，
        /// 确保密钥得到验证并使用正确的算法参数执行操作。
        #[derive(Clone, Debug, Default)]
        pub struct $wrapper;

        impl $wrapper {
            pub fn new() -> Self {
                Self
            }
        }

        impl From<$wrapper> for Box<dyn SymmetricAlgorithmTrait> {
            fn from(wrapper: $wrapper) -> Self {
                Box::new(wrapper)
            }
        }

        impl SymmetricAlgorithmTrait for $wrapper {
            fn encrypt(
                &self,
                plaintext: &[u8],
                key: &TypedSymmetricKey,
                nonce: &[u8],
                aad: Option<&[u8]>,
            ) -> Result<Vec<u8>> {
                if key.algorithm() != $algo_enum {
                    return Err(Error::FormatError(FormatError::InvalidKeyType));
                }
                type KT = $algo;
                let key =
                    <KT as seal_crypto::prelude::SymmetricKeySet>::Key::from_bytes(key.as_bytes())?;
                KT::encrypt(&key, nonce, plaintext, aad).map_err(Error::from)
            }

            fn encrypt_to_buffer(
                &self,
                plaintext: &[u8],
                output: &mut [u8],
                key: &TypedSymmetricKey,
                nonce: &[u8],
                aad: Option<&[u8]>,
            ) -> Result<usize> {
                if key.algorithm() != $algo_enum {
                    return Err(Error::FormatError(FormatError::InvalidKeyType));
                }
                type KT = $algo;
                let key =
                    <KT as seal_crypto::prelude::SymmetricKeySet>::Key::from_bytes(key.as_bytes())?;
                KT::encrypt_to_buffer(&key, nonce, plaintext, output, aad).map_err(Error::from)
            }

            fn decrypt(
                &self,
                ciphertext: &[u8],
                key: &TypedSymmetricKey,
                nonce: &[u8],
                aad: Option<&[u8]>,
            ) -> Result<Vec<u8>> {
                if key.algorithm() != $algo_enum {
                    return Err(Error::FormatError(FormatError::InvalidKeyType));
                }
                type KT = $algo;
                let key =
                    <KT as seal_crypto::prelude::SymmetricKeySet>::Key::from_bytes(key.as_bytes())?;
                KT::decrypt(&key, nonce, ciphertext, aad).map_err(Error::from)
            }

            fn decrypt_to_buffer(
                &self,
                ciphertext: &[u8],
                output: &mut [u8],
                key: &TypedSymmetricKey,
                nonce: &[u8],
                aad: Option<&[u8]>,
            ) -> Result<usize> {
                if key.algorithm() != $algo_enum {
                    return Err(Error::FormatError(FormatError::InvalidKeyType));
                }
                type KT = $algo;
                let key =
                    <KT as seal_crypto::prelude::SymmetricKeySet>::Key::from_bytes(key.as_bytes())?;
                KT::decrypt_to_buffer(&key, nonce, ciphertext, output, aad).map_err(Error::from)
            }

            fn clone_box_symmetric(&self) -> Box<dyn SymmetricAlgorithmTrait> {
                Box::new(self.clone())
            }

            fn algorithm(&self) -> SymmetricAlgorithm {
                $algo_enum
            }

            fn key_size(&self) -> usize {
                <$algo>::KEY_SIZE
            }

            fn nonce_size(&self) -> usize {
                <$algo>::NONCE_SIZE
            }

            fn tag_size(&self) -> usize {
                <$algo>::TAG_SIZE
            }

            fn generate_typed_key(&self) -> Result<TypedSymmetricKey> {
                TypedSymmetricKey::generate($algo_enum)
            }

            fn generate_untyped_key(&self) -> Result<UntypedSymmetricKey> {
                self.generate_typed_key().map(|k| k.untyped())
            }

            fn into_symmetric_boxed(self) -> Box<dyn SymmetricAlgorithmTrait> {
                Box::new(self)
            }
        }
    };
}

/// Universal wrapper for symmetric encryption algorithms.
///
/// 对称加密算法的通用包装器。
///
/// ## Purpose | 目的
///
/// This wrapper provides a unified interface for all symmetric encryption algorithms,
/// allowing runtime algorithm selection while maintaining type safety. It acts as
/// a bridge between algorithm enums and concrete implementations.
///
/// 此包装器为所有对称加密算法提供统一接口，
/// 允许运行时算法选择同时保持类型安全。它充当算法枚举和具体实现之间的桥梁。
///
/// ## Features | 特性
///
/// - **Runtime Polymorphism**: Switch between algorithms at runtime
/// - **Type Safety**: Maintains algorithm-key binding verification
/// - **Unified Interface**: Same API for all symmetric algorithms
/// - **Performance**: Zero-cost abstractions where possible
///
/// - **运行时多态性**: 在运行时切换算法
/// - **类型安全**: 保持算法-密钥绑定验证
/// - **统一接口**: 所有对称算法的相同 API
/// - **性能**: 尽可能的零成本抽象
///
/// ## Examples | 示例
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::symmetric::SymmetricAlgorithm;
/// use seal_crypto_wrapper::wrappers::symmetric::SymmetricAlgorithmWrapper;
///
/// // Create from algorithm enum
/// let algorithm = SymmetricAlgorithm::build().aes256_gcm();
/// let wrapper = SymmetricAlgorithmWrapper::from_enum(algorithm);
///
/// // Use unified interface
/// let key = wrapper.generate_typed_key()?;
/// let plaintext = b"Hello, World!";
/// let nonce = vec![0u8; wrapper.nonce_size()];
/// let ciphertext = wrapper.encrypt(plaintext, &key, &nonce, None)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct SymmetricAlgorithmWrapper {
    pub(crate) algorithm: Box<dyn SymmetricAlgorithmTrait>,
}

impl Deref for SymmetricAlgorithmWrapper {
    type Target = Box<dyn SymmetricAlgorithmTrait>;

    fn deref(&self) -> &Self::Target {
        &self.algorithm
    }
}

impl Into<Box<dyn SymmetricAlgorithmTrait>> for SymmetricAlgorithmWrapper {
    fn into(self) -> Box<dyn SymmetricAlgorithmTrait> {
        self.algorithm
    }
}

impl SymmetricAlgorithmWrapper {
    /// Creates a new wrapper from a boxed trait object.
    ///
    /// 从 boxed trait 对象创建新的包装器。
    ///
    /// This constructor allows you to wrap any implementation of
    /// `SymmetricAlgorithmTrait` in the universal wrapper interface.
    ///
    /// 此构造函数允许您将 `SymmetricAlgorithmTrait` 的任何实现
    /// 包装在通用包装器接口中。
    ///
    /// ## Arguments | 参数
    ///
    /// * `algorithm` - A boxed trait object implementing the symmetric algorithm
    ///
    /// * `algorithm` - 实现对称算法的 boxed trait 对象
    pub fn new(algorithm: Box<dyn SymmetricAlgorithmTrait>) -> Self {
        Self { algorithm }
    }

    /// Creates a wrapper from a symmetric algorithm enum.
    ///
    /// 从对称算法枚举创建包装器。
    ///
    /// This is the most common way to create a wrapper, as it automatically
    /// selects the appropriate concrete implementation based on the algorithm.
    ///
    /// 这是创建包装器的最常见方式，因为它根据算法自动选择适当的具体实现。
    ///
    /// ## Arguments | 参数
    ///
    /// * `algorithm` - The symmetric algorithm enum variant
    ///
    /// * `algorithm` - 对称算法枚举变体
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::symmetric::SymmetricAlgorithm;
    /// use seal_crypto_wrapper::wrappers::symmetric::SymmetricAlgorithmWrapper;
    ///
    /// let aes = SymmetricAlgorithmWrapper::from_enum(
    ///     SymmetricAlgorithm::build().aes256_gcm()
    /// );
    ///
    /// let chacha = SymmetricAlgorithmWrapper::from_enum(
    ///     SymmetricAlgorithm::build().chacha20_poly1305()
    /// );
    /// ```
    pub fn from_enum(algorithm: SymmetricAlgorithm) -> Self {
        let algorithm: Box<dyn SymmetricAlgorithmTrait> = match algorithm {
            SymmetricAlgorithm::AesGcm(AesKeySize::K128) => Box::new(Aes128GcmWrapper::new()),
            SymmetricAlgorithm::AesGcm(AesKeySize::K256) => Box::new(Aes256GcmWrapper::new()),
            SymmetricAlgorithm::ChaCha20Poly1305 => Box::new(ChaCha20Poly1305Wrapper::new()),
            SymmetricAlgorithm::XChaCha20Poly1305 => Box::new(XChaCha20Poly1305Wrapper::new()),
        };
        Self::new(algorithm)
    }

    /// Generates a new algorithm-bound typed key.
    ///
    /// 生成新的算法绑定类型化密钥。
    ///
    /// The generated key is automatically bound to the algorithm used by this wrapper,
    /// ensuring type safety for all subsequent operations.
    ///
    /// 生成的密钥自动绑定到此包装器使用的算法，
    /// 确保所有后续操作的类型安全。
    ///
    /// ## Returns | 返回值
    ///
    /// A new `TypedSymmetricKey` that can only be used with this algorithm.
    ///
    /// 只能与此算法一起使用的新 `TypedSymmetricKey`。
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::symmetric::SymmetricAlgorithm;
    ///
    /// let cipher = SymmetricAlgorithm::build().aes256_gcm().into_symmetric_wrapper();
    /// let key = cipher.generate_typed_key()?;
    ///
    /// // Key is bound to AES-256-GCM
    /// assert_eq!(key.algorithm(), SymmetricAlgorithm::build().aes256_gcm());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate_typed_key(&self) -> Result<TypedSymmetricKey> {
        self.algorithm.generate_typed_key()
    }

    /// Generates a new untyped key.
    ///
    /// 生成新的非类型化密钥。
    ///
    /// This method generates key material without algorithm binding,
    /// which can be useful for key derivation or storage scenarios.
    ///
    /// 此方法生成没有算法绑定的密钥材料，
    /// 这对密钥派生或存储场景很有用。
    ///
    /// ## Security Note | 安全注意
    ///
    /// Untyped keys lose algorithm binding information. Use `generate_typed_key()`
    /// when possible to maintain type safety.
    ///
    /// 非类型化密钥失去算法绑定信息。尽可能使用 `generate_typed_key()`
    /// 以保持类型安全。
    pub fn generate_untyped_key(&self) -> Result<UntypedSymmetricKey> {
        self.algorithm.generate_untyped_key()
    }

    /// Generates a new nonce.
    ///
    /// 生成新的 nonce。
    ///
    /// This method generates a random nonce for the symmetric algorithm.
    ///
    /// 此方法生成对称算法的随机 nonce。
    ///
    /// ## Returns | 返回值
    ///
    /// A new nonce for the symmetric algorithm.
    ///
    /// 对称算法的新的 nonce。
    ///
    pub fn generate_nonce(&self) -> Result<Vec<u8>> {
        let mut nonce = vec![0u8; self.nonce_size()];
        OsRng.try_fill_bytes(&mut nonce)?;
        Ok(nonce)
    }
}

impl SymmetricAlgorithmTrait for SymmetricAlgorithmWrapper {
    fn encrypt(
        &self,
        plaintext: &[u8],
        key: &TypedSymmetricKey,
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.algorithm.encrypt(plaintext, key, nonce, aad)
    }

    fn encrypt_to_buffer(
        &self,
        plaintext: &[u8],
        output: &mut [u8],
        key: &TypedSymmetricKey,
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<usize> {
        self.algorithm
            .encrypt_to_buffer(plaintext, output, key, nonce, aad)
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &TypedSymmetricKey,
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.algorithm.decrypt(ciphertext, key, nonce, aad)
    }

    fn decrypt_to_buffer(
        &self,
        ciphertext: &[u8],
        output: &mut [u8],
        key: &TypedSymmetricKey,
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<usize> {
        self.algorithm
            .decrypt_to_buffer(ciphertext, output, key, nonce, aad)
    }

    fn generate_typed_key(&self) -> Result<TypedSymmetricKey> {
        self.algorithm.generate_typed_key()
    }

    fn generate_untyped_key(&self) -> Result<UntypedSymmetricKey> {
        self.algorithm.generate_untyped_key()
    }

    fn algorithm(&self) -> SymmetricAlgorithm {
        self.algorithm.algorithm()
    }

    fn key_size(&self) -> usize {
        self.algorithm.key_size()
    }

    fn nonce_size(&self) -> usize {
        self.algorithm.nonce_size()
    }

    fn tag_size(&self) -> usize {
        self.algorithm.tag_size()
    }

    fn into_symmetric_boxed(self) -> Box<dyn SymmetricAlgorithmTrait> {
        self.algorithm
    }

    fn clone_box_symmetric(&self) -> Box<dyn SymmetricAlgorithmTrait> {
        Box::new(self.clone())
    }
}

impl From<SymmetricAlgorithm> for SymmetricAlgorithmWrapper {
    fn from(algorithm: SymmetricAlgorithm) -> Self {
        Self::from_enum(algorithm)
    }
}

impl From<Box<dyn SymmetricAlgorithmTrait>> for SymmetricAlgorithmWrapper {
    fn from(algorithm: Box<dyn SymmetricAlgorithmTrait>) -> Self {
        Self::new(algorithm)
    }
}

impl_symmetric_algorithm!(
    Aes128GcmWrapper,
    Aes128Gcm,
    SymmetricAlgorithm::AesGcm(AesKeySize::K128)
);

impl_symmetric_algorithm!(
    Aes256GcmWrapper,
    Aes256Gcm,
    SymmetricAlgorithm::AesGcm(AesKeySize::K256)
);

impl_symmetric_algorithm!(
    ChaCha20Poly1305Wrapper,
    ChaCha20Poly1305,
    SymmetricAlgorithm::ChaCha20Poly1305
);

impl_symmetric_algorithm!(
    XChaCha20Poly1305Wrapper,
    XChaCha20Poly1305,
    SymmetricAlgorithm::XChaCha20Poly1305
);

#[cfg(test)]
mod tests {
    use crate::algorithms::symmetric::SymmetricAlgorithm;
    use crate::keys::symmetric::{SymmetricKey, TypedSymmetricKey};
    #[cfg(feature = "kdf")]
    use crate::algorithms::kdf::{key::KdfKeyAlgorithm, passwd::KdfPasswordAlgorithm};
    use seal_crypto::secrecy::SecretBox;
    #[cfg(feature = "xof")]
    use crate::algorithms::xof::XofAlgorithm;

    #[test]
    fn test_symmetric_key_generate() {
        use crate::keys::symmetric::SymmetricKey;
        use seal_crypto::{prelude::SymmetricCipher, schemes::symmetric::aes_gcm::Aes256Gcm};

        let key_len = <Aes256Gcm as SymmetricCipher>::KEY_SIZE;
        let key1 = SymmetricKey::generate(key_len).unwrap();
        let key2 = SymmetricKey::generate(key_len).unwrap();

        assert_eq!(key1.as_bytes().len(), key_len);
        assert_eq!(key2.as_bytes().len(), key_len);
        assert_ne!(
            key1.as_bytes(),
            key2.as_bytes(),
            "Generated keys should be unique"
        );
    }

    #[test]
    fn test_symmetric_key_from_bytes() {
        let key_bytes = vec![0u8; 32];
        let key = SymmetricKey::new(key_bytes.clone());

        assert_eq!(key.as_bytes(), key_bytes.as_slice());
    }

    #[test]
    #[cfg(feature = "kdf")]
    fn test_typed_symmetric_key_derive_from_kdf() {
        // 使用HKDF-SHA256进行密钥派生
        let master_key_bytes = vec![0u8; 32];

        // 使用不同的上下文信息派生出不同的子密钥
        let salt = b"salt_value";
        let info1 = b"encryption_key";
        let info2 = b"signing_key";
        let kdf_algorithm = KdfKeyAlgorithm::build().hkdf_sha256();
        let symmetric_algorithm = SymmetricAlgorithm::build().aes256_gcm();

        let derived_key1 = TypedSymmetricKey::derive_from_kdf(
            &master_key_bytes,
            kdf_algorithm.clone(),
            Some(salt),
            Some(info1),
            symmetric_algorithm,
        )
        .unwrap();

        let derived_key2 = TypedSymmetricKey::derive_from_kdf(
            &master_key_bytes,
            kdf_algorithm.clone(),
            Some(salt),
            Some(info2),
            symmetric_algorithm,
        )
        .unwrap();

        // 相同的主密钥和参数应该产生相同的派生密钥
        let derived_key1_again = TypedSymmetricKey::derive_from_kdf(
            &master_key_bytes,
            kdf_algorithm.clone(),
            Some(salt),
            Some(info1),
            symmetric_algorithm,
        )
        .unwrap();

        // 不同的上下文信息应该产生不同的派生密钥
        assert_ne!(derived_key1.as_bytes(), derived_key2.as_bytes());

        // 相同的参数应该产生相同的派生密钥
        assert_eq!(derived_key1.as_bytes(), derived_key1_again.as_bytes());

        assert_eq!(derived_key1.algorithm(), symmetric_algorithm);
    }

    #[test]
    #[cfg(feature = "kdf")]
    fn test_typed_symmetric_key_derive_from_password() {
        // 使用PBKDF2-SHA256从密码派生密钥
        let password = SecretBox::new(Box::from(b"my_secure_password".as_slice()));
        let salt = b"random_salt_value";
        let symmetric_algorithm = SymmetricAlgorithm::build().aes256_gcm();

        // 设置较少的迭代次数以加速测试（实际应用中应使用更多迭代）
        let deriver =
            KdfPasswordAlgorithm::build().pbkdf2_sha256_with_params(1000).into_kdf_password_wrapper();

        let derived_key1 =
            TypedSymmetricKey::derive_from_password(&password, deriver.clone(), salt, symmetric_algorithm)
                .unwrap();

        // 相同的密码、盐和迭代次数应该产生相同的密钥
        let derived_key2 =
            TypedSymmetricKey::derive_from_password(&password, deriver.clone(), salt, symmetric_algorithm)
                .unwrap();

        assert_eq!(derived_key1.as_bytes(), derived_key2.as_bytes());

        // 不同的密码应该产生不同的密钥
        let different_password = SecretBox::new(Box::from(b"different_password".as_slice()));
        let derived_key3 = TypedSymmetricKey::derive_from_password(
            &different_password,
            deriver.clone(),
            salt,
            symmetric_algorithm,
        )
        .unwrap();

        assert_ne!(derived_key1.as_bytes(), derived_key3.as_bytes());

        // 不同的盐应该产生不同的密钥
        let different_salt = b"different_salt_value";
        let derived_key4 = TypedSymmetricKey::derive_from_password(
            &password,
            deriver.clone(),
            different_salt,
            symmetric_algorithm,
        )
        .unwrap();

        assert_ne!(derived_key1.as_bytes(), derived_key4.as_bytes());

        assert_eq!(derived_key1.algorithm(), symmetric_algorithm);
    }

    #[test]
    #[cfg(feature = "xof")]
    fn test_typed_symmetric_key_derive_from_xof() {
        use crate::traits::XofAlgorithmTrait;

        let seed = [0u8; 32];
        let symmetric_algo_1 = SymmetricAlgorithm::build().aes128_gcm();
        let symmetric_algo_2 = SymmetricAlgorithm::build().aes256_gcm();

        let mut reader = XofAlgorithm::build()
            .shake128()
            .into_xof_wrapper()
            .reader(&seed, None, None).unwrap();

        let key1 = TypedSymmetricKey::derive_from_xof(&mut reader, symmetric_algo_1).unwrap();
        let key2 = TypedSymmetricKey::derive_from_xof(&mut reader, symmetric_algo_2).unwrap();

        // Keys derived from the same reader should be different
        assert_ne!(key1.as_bytes(), key2.as_bytes());

        // Check key lengths and algorithm binding
        assert_eq!(key1.as_bytes().len(), 16);
        assert_eq!(key1.algorithm(), symmetric_algo_1);

        assert_eq!(key2.as_bytes().len(), 32);
        assert_eq!(key2.algorithm(), symmetric_algo_2);
    }

    #[test]
    #[cfg(feature = "kdf")]
    fn test_kdf_derivation_output_length() {
        let master_key_bytes = vec![0u8; 32];
        let kdf_algorithm = KdfKeyAlgorithm::build().hkdf_sha256();
        let salt = b"salt";
        let info = b"info";

        let sym_alg_128 = SymmetricAlgorithm::build().aes128_gcm();
        let sym_alg_256 = SymmetricAlgorithm::build().aes256_gcm();

        // 测试不同长度的输出
        let key_128 = TypedSymmetricKey::derive_from_kdf(
            &master_key_bytes,
            kdf_algorithm.clone(),
            Some(salt),
            Some(info),
            sym_alg_128,
        )
        .unwrap();
        let key_256 = TypedSymmetricKey::derive_from_kdf(
            &master_key_bytes,
            kdf_algorithm.clone(),
            Some(salt),
            Some(info),
            sym_alg_256,
        )
        .unwrap();

        assert_eq!(key_128.as_bytes().len(), 16);
        assert_eq!(key_128.algorithm(), sym_alg_128);
        assert_eq!(key_256.as_bytes().len(), 32);
        assert_eq!(key_256.algorithm(), sym_alg_256);
    }
}
