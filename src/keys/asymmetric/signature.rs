
use crate::algorithms::asymmetric::signature::{ SignatureAlgorithm};
use crate::error::Error;
use crate::keys::asymmetric::{AsymmetricPrivateKey, AsymmetricPublicKey};
use crate::dispatch_signature;
use seal_crypto::prelude::{Key, KeyGenerator};
use crate::impl_typed_asymmetric_public_key;
use crate::impl_typed_asymmetric_private_key;


/// A struct wrapping a typed signature key pair.
///
/// 包装了类型化签名密钥对的结构体。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TypedSignatureKeyPair {
    public_key: AsymmetricPublicKey,
    private_key: AsymmetricPrivateKey,
    algorithm: SignatureAlgorithm,
}

impl TypedSignatureKeyPair {
    /// Generates a new key pair for the specified algorithm.
    ///
    /// 为指定的算法生成一个新的密钥对。
    pub fn generate(algorithm: SignatureAlgorithm) -> Result<Self, Error> {
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
        dispatch_signature!(algorithm, generate_keypair)
    }

    pub fn into_keypair(self) -> (TypedSignaturePublicKey, TypedSignaturePrivateKey) {
        (
            TypedSignaturePublicKey {
                key: self.public_key,
                algorithm: self.algorithm,
            },
            TypedSignaturePrivateKey {
                key: self.private_key,
                algorithm: self.algorithm,
            },
        )
    }

    /// Returns the public key as a generic byte wrapper.
    ///
    /// 以通用字节包装器形式返回公钥。
    pub fn public_key(&self) -> TypedSignaturePublicKey {
        TypedSignaturePublicKey {
            key: self.public_key.clone(),
            algorithm: self.algorithm,
        }
    }

    /// Returns the private key as a generic byte wrapper.
    ///
    /// 以通用字节包装器形式返回私钥。
    pub fn private_key(&self) -> TypedSignaturePrivateKey {
        TypedSignaturePrivateKey {
            key: self.private_key.clone(),
            algorithm: self.algorithm,
        }
    }

    /// Returns the algorithm of the key pair.
    ///
    /// 返回密钥对的算法。
    pub fn get_algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

/// A struct wrapping a typed signature public key.
///
/// 包装了类型化签名公钥的结构体。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TypedSignaturePublicKey {
    pub(crate) key: AsymmetricPublicKey,
    pub(crate) algorithm: SignatureAlgorithm,
}

impl_typed_asymmetric_public_key!(TypedSignaturePublicKey, SignatureAlgorithm);

/// A struct wrapping a typed signature private key.
///
/// 包装了类型化签名私钥的结构体。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TypedSignaturePrivateKey {
    pub(crate) key: AsymmetricPrivateKey,
    pub(crate) algorithm: SignatureAlgorithm,
}

impl_typed_asymmetric_private_key!(TypedSignaturePrivateKey, SignatureAlgorithm);


