
use crate::dispatch_kem;
use crate::algorithms::asymmetric::kem::KemAlgorithm;
use crate::error::Error;
use seal_crypto::prelude::{Key, KeyGenerator};
use crate::keys::asymmetric::{AsymmetricPrivateKey, AsymmetricPublicKey};
use crate::impl_typed_asymmetric_public_key;
use crate::impl_typed_asymmetric_private_key;
use crate::keys::asymmetric::TypedAsymmetricKeyTrait;
use seal_crypto::zeroize::Zeroizing;



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

    /// Returns the public key with the specified algorithm.
    ///
    /// 以通用字节包装器形式返回公钥。
    pub fn public_key(&self) -> TypedKemPublicKey {
        TypedKemPublicKey {
            key: self.public_key.clone(),
            algorithm: self.algorithm,
        }
    }

    /// Returns the private key with the specified algorithm.
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

/// An enum wrapping a typed asymmetric public key.
///
/// 包装了类型化非对称公钥的枚举。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TypedKemPublicKey {
    pub(crate) key: AsymmetricPublicKey,
    pub(crate) algorithm: KemAlgorithm,
}

impl_typed_asymmetric_public_key!(TypedKemPublicKey, KemAlgorithm);

/// An enum wrapping a typed asymmetric private key.
///
/// 包装了类型化非对称私钥的枚举。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TypedKemPrivateKey {
    pub(crate) key: AsymmetricPrivateKey,
    pub(crate) algorithm: KemAlgorithm,
}

impl_typed_asymmetric_private_key!(TypedKemPrivateKey, KemAlgorithm);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedSecret(pub Zeroizing<Vec<u8>>);

/// An enum wrapping a typed encapsulated key.
///
/// 包装了类型化封装密钥的枚举。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct EncapsulatedKey {
    pub(crate) key: Vec<u8>,
    pub(crate) algorithm: KemAlgorithm,
}

impl EncapsulatedKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.key.as_ref()
    }

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