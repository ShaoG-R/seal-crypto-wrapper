use crate::algorithms::signature::{DilithiumSecurityLevel, SignatureAlgorithm};
use crate::error::Error;
use seal_crypto::prelude::{AsymmetricKeySet, Key, KeyGenerator};
use seal_crypto::schemes::asymmetric::post_quantum::dilithium::{
    Dilithium2, Dilithium3, Dilithium5,
};
use seal_crypto::schemes::asymmetric::traditional::ecc::{EcdsaP256, Ed25519};
use seal_crypto::zeroize;

macro_rules! dispatch_signature {
    ($algorithm:expr, $action:ident) => {
        match $algorithm {
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L2) => {
                $action!(
                    Dilithium2,
                    SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L2)
                )
            }
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L3) => {
                $action!(
                    Dilithium3,
                    SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L3)
                )
            }
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L5) => {
                $action!(
                    Dilithium5,
                    SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L5)
                )
            }
            SignatureAlgorithm::Ed25519 => $action!(Ed25519, SignatureAlgorithm::Ed25519),
            SignatureAlgorithm::EcdsaP256 => {
                $action!(EcdsaP256, SignatureAlgorithm::EcdsaP256)
            }
        }
    };
}

/// A struct wrapping a typed signature key pair.
///
/// 包装了类型化签名密钥对的结构体。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TypedSignatureKeyPair {
    public_key: SignaturePublicKey,
    private_key: SignaturePrivateKey,
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
                        public_key: SignaturePublicKey::new(pk.to_bytes()),
                        private_key: SignaturePrivateKey::new(sk.to_bytes()),
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
    key: SignaturePublicKey,
    algorithm: SignatureAlgorithm,
}

impl TypedSignaturePublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.as_bytes().to_vec()
    }

    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

/// A struct wrapping a typed signature private key.
///
/// 包装了类型化签名私钥的结构体。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TypedSignaturePrivateKey {
    key: SignaturePrivateKey,
    algorithm: SignatureAlgorithm,
}

impl TypedSignaturePrivateKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.as_bytes().to_vec()
    }

    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

/// A byte wrapper for a signature public key.
///
/// 签名公钥的字节包装器。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignaturePublicKey(pub zeroize::Zeroizing<Vec<u8>>);

impl SignaturePublicKey {
    /// Create a new signature public key from bytes
    ///
    /// 从字节创建一个新的签名公钥
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

    /// Converts the raw key bytes into a typed public key struct.
    ///
    /// 将原始密钥字节转换为类型化的公钥结构体。
    pub fn into_typed(
        self,
        algorithm: SignatureAlgorithm,
    ) -> Result<TypedSignaturePublicKey, Error> {
        macro_rules! into_typed_pk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let pk = <KT as AsymmetricKeySet>::PublicKey::from_bytes(self.as_bytes())?;
                Ok(TypedSignaturePublicKey {
                    key: SignaturePublicKey::new(pk.to_bytes()),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_signature!(algorithm, into_typed_pk)
    }
}

/// A byte wrapper for a signature private key.
///
/// 签名私钥的字节包装器。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignaturePrivateKey(pub zeroize::Zeroizing<Vec<u8>>);

impl SignaturePrivateKey {
    /// Create a new signature private key from bytes
    ///
    /// 从字节创建一个新的签名私钥
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

    /// Converts the raw key bytes into a typed private key struct.
    ///
    /// 将原始密钥字节转换为类型化的私钥结构体。
    pub fn into_typed(
        self,
        algorithm: SignatureAlgorithm,
    ) -> Result<TypedSignaturePrivateKey, Error> {
        macro_rules! into_typed_sk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let sk = <KT as AsymmetricKeySet>::PrivateKey::from_bytes(self.as_bytes())?;
                Ok(TypedSignaturePrivateKey {
                    key: SignaturePrivateKey::new(sk.to_bytes()),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_signature!(algorithm, into_typed_sk)
    }
}
