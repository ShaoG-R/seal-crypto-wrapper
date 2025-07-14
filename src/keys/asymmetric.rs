use seal_crypto::schemes::asymmetric::traditional::rsa::{Rsa2048, Rsa4096};
use seal_crypto::schemes::hash::{Sha256, Sha384, Sha512};
use seal_crypto::prelude::{AsymmetricKeySet, Key, KeyGenerator};
use seal_crypto::schemes::asymmetric::post_quantum::kyber::{Kyber1024, Kyber512, Kyber768};
use crate::algorithms::{
    asymmetric::{AsymmetricAlgorithm, KyberSecurityLevel, RsaBits}, HashAlgorithmEnum
};
use crate::error::Error;
use seal_crypto::zeroize;

macro_rules! dispatch_asymmetric {
    ($algorithm:expr, $action:ident) => {
        match $algorithm {
            AsymmetricAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha256) => {
                $action!(Rsa2048<Sha256>, AsymmetricAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha256))
            }
            AsymmetricAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha384) => {
                $action!(Rsa2048<Sha384>, AsymmetricAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha384))
            }
            AsymmetricAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha512) => {
                $action!(Rsa2048<Sha512>, AsymmetricAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha512))
            }
            AsymmetricAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha256) => {
                $action!(Rsa4096<Sha256>, AsymmetricAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha256))
            }
            AsymmetricAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha384) => {
                $action!(Rsa4096<Sha384>, AsymmetricAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha384))
            }
            AsymmetricAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha512) => {
                $action!(Rsa4096<Sha512>, AsymmetricAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha512))
            }
            AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L512) => {
                $action!(Kyber512, AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L512))
            }
            AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L768) => {
                $action!(Kyber768, AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L768))
            }
            AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L1024) => {
                $action!(Kyber1024, AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L1024))
            }
        }
    };
}

/// An enum wrapping a typed asymmetric key pair.
///
/// 包装了类型化非对称密钥对的枚举。
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, Debug)]
pub struct TypedAsymmetricKeyPair {
    public_key: AsymmetricPublicKey,
    private_key: AsymmetricPrivateKey,
    algorithm: AsymmetricAlgorithm,
}

impl TypedAsymmetricKeyPair {
    /// Generates a new key pair for the specified algorithm.
    ///
    /// 为指定的算法生成一个新的密钥对。
    pub fn generate(algorithm: AsymmetricAlgorithm) -> Result<Self, Error> {
        macro_rules! generate_keypair {
            ($key_type:ty, $alg_enum:expr) => {
                <$key_type>::generate_keypair().map(|(pk, sk)| Self {
                    public_key: AsymmetricPublicKey::new(pk.to_bytes()),
                    private_key: AsymmetricPrivateKey::new(sk.to_bytes()),
                    algorithm: $alg_enum,
                }).map_err(Error::from)
            };
        }
        dispatch_asymmetric!(algorithm, generate_keypair)
    }

    pub fn into_keypair(self) -> (TypedAsymmetricPublicKey, TypedAsymmetricPrivateKey) {
        (
            TypedAsymmetricPublicKey {
                key: self.public_key,
                algorithm: self.algorithm,
            },
            TypedAsymmetricPrivateKey {
                key: self.private_key,
                algorithm: self.algorithm,
            },
        )
    }

    /// Returns the public key as a generic byte wrapper.
    ///
    /// 以通用字节包装器形式返回公钥。
    pub fn public_key(&self) -> TypedAsymmetricPublicKey {
        TypedAsymmetricPublicKey {
            key: self.public_key.clone(),
            algorithm: self.algorithm,
        }
    }

    /// Returns the private key as a generic byte wrapper.
    ///
    /// 以通用字节包装器形式返回私钥。
    pub fn private_key(&self) -> TypedAsymmetricPrivateKey {
        TypedAsymmetricPrivateKey {
            key: self.private_key.clone(),
            algorithm: self.algorithm,
        }
    }

    /// Returns the algorithm of the key pair.
    ///
    /// 返回密钥对的算法。
    pub fn algorithm(&self) -> AsymmetricAlgorithm {
        self.algorithm
    }
}

/// An enum wrapping a typed asymmetric private key.
///
/// 包装了类型化非对称私钥的枚举。
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, Debug)]
pub struct TypedAsymmetricPublicKey {
    key: AsymmetricPublicKey,
    algorithm: AsymmetricAlgorithm,
}

impl TypedAsymmetricPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.as_bytes().to_vec()
    }

    pub fn algorithm(&self) -> AsymmetricAlgorithm {
        self.algorithm
    }
}

/// An enum wrapping a typed asymmetric private key.
///
/// 包装了类型化非对称私钥的枚举。
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, Debug)]
pub struct TypedAsymmetricPrivateKey {
    key: AsymmetricPrivateKey,
    algorithm: AsymmetricAlgorithm,
}

impl TypedAsymmetricPrivateKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.as_bytes().to_vec()
    }

    pub fn algorithm(&self) -> AsymmetricAlgorithm {
        self.algorithm
    }
}

/// A byte wrapper for an asymmetric private key.
///
/// 非对称私钥的字节包装器。
#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
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
    pub fn into_typed(
        self,
        algorithm: AsymmetricAlgorithm,
    ) -> Result<TypedAsymmetricPrivateKey, Error> {
        macro_rules! into_typed_sk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let sk =
                    <KT as AsymmetricKeySet>::PrivateKey::from_bytes(self.as_bytes())?;
                Ok(TypedAsymmetricPrivateKey {
                    key: AsymmetricPrivateKey::new(sk.to_bytes()),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_asymmetric!(algorithm, into_typed_sk)
    }
}

/// A byte wrapper for an asymmetric public key.
///
/// 非对称公钥的字节包装器。
#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
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

    pub fn into_typed(
        self,
        algorithm: AsymmetricAlgorithm,
    ) -> Result<TypedAsymmetricPublicKey, Error> {
        macro_rules! into_typed_pk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let pk =
                    <KT as AsymmetricKeySet>::PublicKey::from_bytes(self.as_bytes())?;
                Ok(TypedAsymmetricPublicKey {
                    key: AsymmetricPublicKey::new(pk.to_bytes()),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_asymmetric!(algorithm, into_typed_pk)
    }
}