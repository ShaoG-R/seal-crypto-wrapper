use crate::algorithms::kdf::key::KdfKeyAlgorithm;
use crate::algorithms::symmetric::{AesKeySize, SymmetricAlgorithm};
use crate::error::Error;
use crate::wrappers::kdf::passwd::KdfPasswordWrapper;
use seal_crypto::prelude::{Key, SymmetricKeyGenerator, SymmetricKeySet};
use seal_crypto::schemes::symmetric::aes_gcm::{Aes128Gcm, Aes256Gcm};
use seal_crypto::schemes::symmetric::chacha20_poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use seal_crypto::secrecy::SecretBox;
use seal_crypto::zeroize::Zeroizing;

macro_rules! dispatch_symmetric {
    ($algorithm:expr, $action:ident) => {
        match $algorithm {
            SymmetricAlgorithm::AesGcm(AesKeySize::K128) => {
                $action!(Aes128Gcm, SymmetricAlgorithm::AesGcm(AesKeySize::K128))
            }
            SymmetricAlgorithm::AesGcm(AesKeySize::K256) => {
                $action!(Aes256Gcm, SymmetricAlgorithm::AesGcm(AesKeySize::K256))
            }
            SymmetricAlgorithm::XChaCha20Poly1305 => {
                $action!(XChaCha20Poly1305, SymmetricAlgorithm::XChaCha20Poly1305)
            }
            SymmetricAlgorithm::ChaCha20Poly1305 => {
                $action!(ChaCha20Poly1305, SymmetricAlgorithm::ChaCha20Poly1305)
            }
        }
    };
}

/// A struct wrapping a typed symmetric key.
///
/// 包装了类型化对称密钥的结构体。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TypedSymmetricKey {
    key: SymmetricKey,
    algorithm: SymmetricAlgorithm,
}

impl TypedSymmetricKey {
    pub fn generate(algorithm: SymmetricAlgorithm) -> Result<Self, Error> {
        macro_rules! generate_key {
            ($key_type:ty, $alg_enum:expr) => {
                <$key_type>::generate_key()
                    .map(|k| Self {
                        key: SymmetricKey::new(k.to_bytes()),
                        algorithm: $alg_enum,
                    })
                    .map_err(Error::from)
            };
        }
        dispatch_symmetric!(algorithm, generate_key)
    }

    pub fn from_bytes(bytes: &[u8], algorithm: SymmetricAlgorithm) -> Result<Self, Error> {
        let key = SymmetricKey::new(bytes.to_vec());
        key.into_typed(algorithm)
    }

    pub fn algorithm(&self) -> SymmetricAlgorithm {
        self.algorithm
    }

    pub fn untyped(&self) -> SymmetricKey {
        self.key.clone()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.key.as_bytes()
    }

    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.key.into_bytes()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes()
    }
}

impl AsRef<[u8]> for TypedSymmetricKey {
    fn as_ref(&self) -> &[u8] {
        self.key.as_bytes()
    }
}

/// A byte wrapper for a symmetric encryption key.
///
/// This struct stores raw key bytes that can be converted to specific algorithm keys
/// when needed. This simplifies key management while maintaining flexibility.
///
/// 对称加密密钥的字节包装器。
///
/// 这个结构体存储原始密钥字节，可以在需要时转换为特定算法的密钥。
/// 这在简化密钥管理的同时保持了灵活性的。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SymmetricKey(pub Zeroizing<Vec<u8>>);

impl SymmetricKey {
    /// Create a new symmetric key from bytes
    ///
    /// 从字节创建一个新的对称密钥
    pub fn new(bytes: impl Into<Zeroizing<Vec<u8>>>) -> Self {
        Self(bytes.into())
    }

    /// Generates a new random symmetric key of the specified length.
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

    /// Converts the raw key bytes into a typed symmetric key enum.
    ///
    /// 将原始密钥字节转换为类型化的对称密钥枚举。
    pub fn into_typed(self, algorithm: SymmetricAlgorithm) -> Result<TypedSymmetricKey, Error> {
        macro_rules! into_typed_key {
            ($key_type:ty, $alg_enum:expr) => {{
                let key = <$key_type as SymmetricKeySet>::Key::from_bytes(self.as_bytes())?;
                Ok(TypedSymmetricKey {
                    key: SymmetricKey::new(key.to_bytes()),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_symmetric!(algorithm, into_typed_key)
    }

    /// Derives a new symmetric key from the current key using a specified key-based KDF.
    ///
    /// This is suitable for key rotation, where a master key is used to generate
    /// sub-keys for specific purposes.
    ///
    /// # Type Parameters
    ///
    /// * `K` - The type of the key-based derivation algorithm, which must implement `KeyBasedDerivation`.
    ///
    /// # Arguments
    ///
    /// * `deriver` - An instance of the key-based KDF scheme (e.g., `HkdfSha256`).
    /// * `salt` - An optional salt. While optional in HKDF, providing a salt is highly recommended.
    /// * `info` - Optional context-specific information.
    /// * `output_len` - The desired length of the derived key in bytes.
    pub fn derive_key(
        &self,
        algorithm: KdfKeyAlgorithm,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Self, Error> {
        use crate::traits::KdfKeyAlgorithmTrait;

        let derived_key_bytes =
            algorithm
                .into_kdf_key_wrapper()
                .derive(self.as_bytes(), salt, info, output_len)?;
        Ok(SymmetricKey::new(derived_key_bytes))
    }

    /// Derives a symmetric key from a password using a specified password-based KDF.
    ///
    /// This is ideal for generating a cryptographic key from a low-entropy user password.
    /// The concrete algorithm instance (e.g., `Pbkdf2Sha256`) should be configured
    /// with the desired number of iterations before being passed to this function.
    ///
    /// # Type Parameters
    ///
    /// * `P` - The type of the password-based derivation algorithm, which must implement `PasswordBasedDerivation`.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to derive the key from.
    /// * `deriver` - An instance of the password-based KDF scheme (e.g., `Pbkdf2Sha256::new(100_000)`).
    /// * `salt` - A salt. This is **required** for password-based derivation to be secure.
    /// * `output_len` - The desired length of the derived key in bytes.
    pub fn derive_from_password(
        password: &SecretBox<[u8]>,
        algorithm: KdfPasswordWrapper,
        salt: &[u8],
        output_len: usize,
    ) -> Result<Self, Error> {
        use crate::traits::KdfPasswordAlgorithmTrait;
        let derived_key_bytes = algorithm.derive(password, salt, output_len)?;
        Ok(SymmetricKey::new(derived_key_bytes))
    }
}
