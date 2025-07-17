use crate::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;
use crate::error::Error;
use seal_crypto::prelude::{AsymmetricKeySet, Key, KeyGenerator};
use seal_crypto::schemes::asymmetric::traditional::ecdh::EcdhP256;
use seal_crypto::zeroize;

macro_rules! dispatch_key_agreement {
    ($algorithm:expr, $action:ident) => {
        match $algorithm {
            KeyAgreementAlgorithm::EcdhP256 => {
                $action!(EcdhP256, KeyAgreementAlgorithm::EcdhP256)
            }
        }
    };
}

/// A struct wrapping a typed key agreement key pair.
///
/// 包装了类型化密钥协商密钥对的结构体。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TypedKeyAgreementKeyPair {
    public_key: KeyAgreementPublicKey,
    private_key: KeyAgreementPrivateKey,
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
                        public_key: KeyAgreementPublicKey::new(pk.to_bytes()),
                        private_key: KeyAgreementPrivateKey::new(sk.to_bytes()),
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
    key: KeyAgreementPublicKey,
    algorithm: KeyAgreementAlgorithm,
}

impl TypedKeyAgreementPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.as_bytes().to_vec()
    }

    pub fn algorithm(&self) -> KeyAgreementAlgorithm {
        self.algorithm
    }
}

/// A struct wrapping a typed key agreement private key.
///
/// 包装了类型化密钥协商私钥的结构体。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TypedKeyAgreementPrivateKey {
    key: KeyAgreementPrivateKey,
    algorithm: KeyAgreementAlgorithm,
}

impl TypedKeyAgreementPrivateKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.as_bytes().to_vec()
    }

    pub fn algorithm(&self) -> KeyAgreementAlgorithm {
        self.algorithm
    }
}

/// A byte wrapper for a key agreement public key.
///
/// 密钥协商公钥的字节包装器。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyAgreementPublicKey(pub zeroize::Zeroizing<Vec<u8>>);

impl KeyAgreementPublicKey {
    /// Create a new key agreement public key from bytes
    ///
    /// 从字节创建一个新的密钥协商公钥
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
        algorithm: KeyAgreementAlgorithm,
    ) -> Result<TypedKeyAgreementPublicKey, Error> {
        macro_rules! into_typed_pk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let pk = <KT as AsymmetricKeySet>::PublicKey::from_bytes(self.as_bytes())?;
                Ok(TypedKeyAgreementPublicKey {
                    key: KeyAgreementPublicKey::new(pk.to_bytes()),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_key_agreement!(algorithm, into_typed_pk)
    }
}

/// A byte wrapper for a key agreement private key.
///
/// 密钥协商私钥的字节包装器。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyAgreementPrivateKey(pub zeroize::Zeroizing<Vec<u8>>);

impl KeyAgreementPrivateKey {
    /// Create a new key agreement private key from bytes
    ///
    /// 从字节创建一个新的密钥协商私钥
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
        algorithm: KeyAgreementAlgorithm,
    ) -> Result<TypedKeyAgreementPrivateKey, Error> {
        macro_rules! into_typed_sk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let sk = <KT as AsymmetricKeySet>::PrivateKey::from_bytes(self.as_bytes())?;
                Ok(TypedKeyAgreementPrivateKey {
                    key: KeyAgreementPrivateKey::new(sk.to_bytes()),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_key_agreement!(algorithm, into_typed_sk)
    }
}
