use seal_crypto::prelude::Key;
use seal_crypto::prelude::KeyGenerator;
use crate::keys::asymmetric::RsaBits;
use crate::keys::asymmetric::KyberSecurityLevel;
use crate::keys::asymmetric::HashAlgorithmEnum;
use crate::algorithms::asymmetric::kem::KemAlgorithm;
use crate::error::Error;
use crate::keys::asymmetric::{AsymmetricPrivateKey, AsymmetricPublicKey};


use seal_crypto::schemes::asymmetric::post_quantum::kyber::{Kyber1024, Kyber512, Kyber768};
use seal_crypto::schemes::asymmetric::traditional::rsa::{Rsa2048, Rsa4096};
use seal_crypto::schemes::hash::{Sha256, Sha384, Sha512};
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


/// An enum wrapping a typed asymmetric key pair.
///
/// 包装了类型化非对称密钥对的枚举。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TypedKemKeyPair {
    pub(crate) public_key: AsymmetricPublicKey,
    pub(crate) private_key: AsymmetricPrivateKey,
    pub(crate) algorithm: KemAlgorithm,
}

impl TypedKemKeyPair {
    /// Generates a new key pair for the specified algorithm.
    ///
    /// 为指定的算法生成一个新的密钥对。
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

    /// Returns the public key as a generic byte wrapper.
    ///
    /// 以通用字节包装器形式返回公钥。
    pub fn public_key(&self) -> TypedKemPublicKey {
        TypedKemPublicKey {
            key: self.public_key.clone(),
            algorithm: self.algorithm,
        }
    }

    /// Returns the private key as a generic byte wrapper.
    ///
    /// 以通用字节包装器形式返回私钥。
    pub fn private_key(&self) -> TypedKemPrivateKey {
        TypedKemPrivateKey {
            key: self.private_key.clone(),
            algorithm: self.algorithm,
        }
    }

    /// Returns the algorithm of the key pair.
    ///
    /// 返回密钥对的算法。
    pub fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }
}

/// An enum wrapping a typed asymmetric private key.
///
/// 包装了类型化非对称私钥的枚举。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TypedKemPublicKey {
    pub(crate) key: AsymmetricPublicKey,
    pub(crate) algorithm: KemAlgorithm,
}

impl TypedKemPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.as_bytes().to_vec()
    }

    pub fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }
}

/// An enum wrapping a typed asymmetric private key.
///
/// 包装了类型化非对称私钥的枚举。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TypedKemPrivateKey {
    pub(crate) key: AsymmetricPrivateKey,
    pub(crate) algorithm: KemAlgorithm,
}

impl TypedKemPrivateKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.as_bytes().to_vec()
    }

    pub fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }
}