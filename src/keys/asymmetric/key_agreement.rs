use crate::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;
use crate::error::Error;
use crate::keys::asymmetric::{AsymmetricPrivateKey, AsymmetricPublicKey};
use crate::dispatch_key_agreement;
use seal_crypto::prelude::{Key, KeyGenerator};
use crate::impl_typed_asymmetric_public_key;
use crate::impl_typed_asymmetric_private_key;


/// A struct wrapping a typed key agreement key pair.
///
/// 包装了类型化密钥协商密钥对的结构体。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TypedKeyAgreementKeyPair {
    public_key: AsymmetricPublicKey,
    private_key: AsymmetricPrivateKey,
    algorithm: KeyAgreementAlgorithm,
}

impl TypedKeyAgreementKeyPair {
    /// Generates a new key pair for the specified algorithm.
    ///
    /// 为指定的算法生成一个新的密钥对。
    pub fn generate(algorithm: KeyAgreementAlgorithm) -> Result<Self, Error> {
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
        dispatch_key_agreement!(algorithm, generate_keypair)
    }

    pub fn into_keypair(self) -> (TypedKeyAgreementPublicKey, TypedKeyAgreementPrivateKey) {
        (
            TypedKeyAgreementPublicKey {
                key: self.public_key,
                algorithm: self.algorithm,
            },
            TypedKeyAgreementPrivateKey {
                key: self.private_key,
                algorithm: self.algorithm,
            },
        )
    }

    /// Returns the public key as a generic byte wrapper.
    ///
    /// 以通用字节包装器形式返回公钥。
    pub fn public_key(&self) -> TypedKeyAgreementPublicKey {
        TypedKeyAgreementPublicKey {
            key: self.public_key.clone(),
            algorithm: self.algorithm,
        }
    }

    /// Returns the private key as a generic byte wrapper.
    ///
    /// 以通用字节包装器形式返回私钥。
    pub fn private_key(&self) -> TypedKeyAgreementPrivateKey {
        TypedKeyAgreementPrivateKey {
            key: self.private_key.clone(),
            algorithm: self.algorithm,
        }
    }

    /// Returns the algorithm of the key pair.
    ///
    /// 返回密钥对的算法。
    pub fn get_algorithm(&self) -> KeyAgreementAlgorithm {
        self.algorithm
    }
}

/// A struct wrapping a typed key agreement public key.
///
/// 包装了类型化密钥协商公钥的结构体。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TypedKeyAgreementPublicKey {
    pub(crate) key: AsymmetricPublicKey,
    pub(crate) algorithm: KeyAgreementAlgorithm,
}

impl_typed_asymmetric_public_key!(TypedKeyAgreementPublicKey, KeyAgreementAlgorithm);

/// A struct wrapping a typed key agreement private key.
///
/// 包装了类型化密钥协商私钥的结构体。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TypedKeyAgreementPrivateKey {
    pub(crate) key: AsymmetricPrivateKey,
    pub(crate) algorithm: KeyAgreementAlgorithm,
}

impl_typed_asymmetric_private_key!(TypedKeyAgreementPrivateKey, KeyAgreementAlgorithm);


