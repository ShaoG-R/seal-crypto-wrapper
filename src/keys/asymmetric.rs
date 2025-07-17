use crate::algorithms::{
    asymmetric::kem::{KemAlgorithm, KyberSecurityLevel, RsaBits},
    HashAlgorithmEnum,
};
use crate::error::Error;
use seal_crypto::prelude::{AsymmetricKeySet, Key};
use seal_crypto::schemes::asymmetric::post_quantum::kyber::{Kyber1024, Kyber512, Kyber768};
use seal_crypto::schemes::asymmetric::traditional::rsa::{Rsa2048, Rsa4096};
use seal_crypto::schemes::hash::{Sha256, Sha384, Sha512};
use seal_crypto::zeroize;
use kem::{TypedKemPrivateKey, TypedKemPublicKey};

#[cfg(feature = "asymmetric-signature")]
pub mod signature;

#[cfg(feature = "asymmetric-kem")]
pub mod kem;

#[cfg(feature = "asymmetric-key-agreement")]
pub mod key_agreement;

macro_rules! dispatch_kem {
    ($algorithm:expr, $action:ident) => {
        match $algorithm {
            KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha256) => {
                $action!(
                    Rsa2048<Sha256>,
                    KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha256)
                )
            }
            KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha384) => {
                $action!(
                    Rsa2048<Sha384>,
                    KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha384)
                )
            }
            KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha512) => {
                $action!(
                    Rsa2048<Sha512>,
                    KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha512)
                )
            }
            KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha256) => {
                $action!(
                    Rsa4096<Sha256>,
                    KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha256)
                )
            }
            KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha384) => {
                $action!(
                    Rsa4096<Sha384>,
                    KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha384)
                )
            }
            KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha512) => {
                $action!(
                    Rsa4096<Sha512>,
                    KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha512)
                )
            }
            KemAlgorithm::Kyber(KyberSecurityLevel::L512) => {
                $action!(
                    Kyber512,
                    KemAlgorithm::Kyber(KyberSecurityLevel::L512)
                )
            }
            KemAlgorithm::Kyber(KyberSecurityLevel::L768) => {
                $action!(
                    Kyber768,
                    KemAlgorithm::Kyber(KyberSecurityLevel::L768)
                )
            }
            KemAlgorithm::Kyber(KyberSecurityLevel::L1024) => {
                $action!(
                    Kyber1024,
                    KemAlgorithm::Kyber(KyberSecurityLevel::L1024)
                )
            }
        }
    };
}

/// A byte wrapper for an asymmetric private key.
///
/// 非对称私钥的字节包装器。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AsymmetricPrivateKey(pub zeroize::Zeroizing<Vec<u8>>);

impl AsymmetricPrivateKey {
    /// Create a new asymmetric private key from bytes
    ///
    /// 从字节创建一个新的非对称私钥
    pub fn new(bytes: impl Into<zeroize::Zeroizing<Vec<u8>>>) -> Self {
        Self(bytes.into())
    }

    /// Get a reference to the raw bytes of the key
    ///
    /// 获取密钥原始字节的引用
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the key and return the inner bytes
    ///
    /// 消耗密钥并返回内部字节
    pub fn into_bytes(self) -> zeroize::Zeroizing<Vec<u8>> {
        self.0
    }

    /// Converts the raw key bytes into a typed private key enum.
    ///
    /// 将原始密钥字节转换为类型化的私钥枚举。
    pub fn into_kem_typed(
        self,
        algorithm: KemAlgorithm,
    ) -> Result<TypedKemPrivateKey, Error> {
        macro_rules! into_typed_sk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let sk = <KT as AsymmetricKeySet>::PrivateKey::from_bytes(self.as_bytes())?;
                Ok(TypedKemPrivateKey {
                    key: AsymmetricPrivateKey::new(sk.to_bytes()),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_kem!(algorithm, into_typed_sk)
    }
}

/// A byte wrapper for an asymmetric public key.
///
/// 非对称公钥的字节包装器。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AsymmetricPublicKey(pub zeroize::Zeroizing<Vec<u8>>);

impl AsymmetricPublicKey {
    /// Create a new asymmetric public key from bytes
    ///
    /// 从字节创建一个新的非对称公钥
    pub fn new(bytes: impl Into<zeroize::Zeroizing<Vec<u8>>>) -> Self {
        Self(bytes.into())
    }

    /// Get a reference to the raw bytes of the key
    ///
    /// 获取密钥原始字节的引用
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the key and return the inner bytes
    ///
    /// 消耗密钥并返回内部字节
    pub fn into_bytes(self) -> zeroize::Zeroizing<Vec<u8>> {
        self.0
    }

    pub fn into_kem_typed(
        self,
        algorithm: KemAlgorithm,
    ) -> Result<TypedKemPublicKey, Error> {
        macro_rules! into_typed_pk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let pk = <KT as AsymmetricKeySet>::PublicKey::from_bytes(self.as_bytes())?;
                Ok(TypedKemPublicKey {
                    key: AsymmetricPublicKey::new(pk.to_bytes()),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_kem!(algorithm, into_typed_pk)
    }
}
