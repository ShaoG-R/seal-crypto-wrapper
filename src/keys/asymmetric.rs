use crate::error::Error;
use seal_crypto::prelude::{AsymmetricKeySet, Key};
use seal_crypto::zeroize;

#[cfg(feature = "asymmetric-kem")]
use {
    kem::{TypedKemPrivateKey, TypedKemPublicKey},
    crate::algorithms::asymmetric::kem::KemAlgorithm,
};

#[cfg(feature = "asymmetric-key-agreement")]
use crate::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;

#[cfg(feature = "asymmetric-signature")]
use crate::algorithms::asymmetric::signature::SignatureAlgorithm;

#[cfg(feature = "asymmetric-signature")]
pub mod signature;

#[cfg(feature = "asymmetric-kem")]
pub mod kem;

#[cfg(feature = "asymmetric-key-agreement")]
pub mod key_agreement;

#[cfg(feature = "asymmetric-kem")]
#[macro_export(local_inner_macros)]
macro_rules! dispatch_kem {
    ($algorithm:expr, $action:ident) => {{
        use ::seal_crypto::schemes::asymmetric::traditional::rsa::{Rsa2048, Rsa4096};
        use ::seal_crypto::schemes::hash::{Sha256, Sha384, Sha512};
        use ::seal_crypto::schemes::asymmetric::post_quantum::kyber::{Kyber1024, Kyber512, Kyber768};
        use crate::algorithms::asymmetric::kem::{KemAlgorithm, KyberSecurityLevel, RsaBits};
        use crate::algorithms::HashAlgorithmEnum;
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
    }};
}

#[cfg(feature = "asymmetric-signature")]
#[macro_export(local_inner_macros)]
macro_rules! dispatch_signature {
    ($algorithm:expr, $action:ident) => {{
        use ::seal_crypto::schemes::asymmetric::traditional::ecc::{EcdsaP256, Ed25519};
        use crate::algorithms::asymmetric::signature::{DilithiumSecurityLevel, SignatureAlgorithm};
        match $algorithm {
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L2) => {
                $action!(
                    ::seal_crypto::schemes::asymmetric::post_quantum::dilithium::Dilithium2,
                    SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L2)
                )
            }
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L3) => {
                $action!(
                    ::seal_crypto::schemes::asymmetric::post_quantum::dilithium::Dilithium3,
                    SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L3)
                )
            }
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L5) => {
                $action!(
                    ::seal_crypto::schemes::asymmetric::post_quantum::dilithium::Dilithium5,
                    SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L5)
                )
            }
            SignatureAlgorithm::Ed25519 => $action!(Ed25519, SignatureAlgorithm::Ed25519),
            SignatureAlgorithm::EcdsaP256 => {
                $action!(EcdsaP256, SignatureAlgorithm::EcdsaP256)
            }
        }
    }};
}

#[cfg(feature = "asymmetric-key-agreement")]
#[macro_export(local_inner_macros)]
macro_rules! dispatch_key_agreement {
    ($algorithm:expr, $action:ident) => {{
        use ::seal_crypto::schemes::asymmetric::traditional::ecdh::EcdhP256;
        use crate::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;
        match $algorithm {
            KeyAgreementAlgorithm::EcdhP256 => {
                $action!(EcdhP256, KeyAgreementAlgorithm::EcdhP256)
            }
        }
    }};
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

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
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

    /// Converts the raw key bytes into a typed signature private key.
    ///
    /// 将原始密钥字节转换为类型化的签名私钥。
    #[cfg(feature = "asymmetric-signature")]
    pub fn into_signature_typed(
        self,
        algorithm: SignatureAlgorithm,
    ) -> Result<signature::TypedSignaturePrivateKey, Error> {
        use signature::TypedSignaturePrivateKey;
        macro_rules! into_typed_sk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let sk = <KT as AsymmetricKeySet>::PrivateKey::from_bytes(self.as_bytes())?;
                Ok(TypedSignaturePrivateKey {
                    key: AsymmetricPrivateKey::new(sk.to_bytes()),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_signature!(algorithm, into_typed_sk)
    }

    /// Converts the raw key bytes into a typed key agreement private key.
    ///
    /// 将原始密钥字节转换为类型化的密钥协商私钥。
    #[cfg(feature = "asymmetric-key-agreement")]
    pub fn into_key_agreement_typed(
        self,
        algorithm: KeyAgreementAlgorithm,
    ) -> Result<key_agreement::TypedKeyAgreementPrivateKey, Error> {
        use key_agreement::TypedKeyAgreementPrivateKey;
        macro_rules! into_typed_sk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let sk = <KT as AsymmetricKeySet>::PrivateKey::from_bytes(self.as_bytes())?;
                Ok(TypedKeyAgreementPrivateKey {
                    key: AsymmetricPrivateKey::new(sk.to_bytes()),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_key_agreement!(algorithm, into_typed_sk)
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

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
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

    /// Converts the raw key bytes into a typed signature public key.
    ///
    /// 将原始密钥字节转换为类型化的签名公钥。
    #[cfg(feature = "asymmetric-signature")]
    pub fn into_signature_typed(
        self,
        algorithm: SignatureAlgorithm,
    ) -> Result<signature::TypedSignaturePublicKey, Error> {
        use signature::TypedSignaturePublicKey;
        macro_rules! into_typed_pk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let pk = <KT as AsymmetricKeySet>::PublicKey::from_bytes(self.as_bytes())?;
                Ok(TypedSignaturePublicKey {
                    key: AsymmetricPublicKey::new(pk.to_bytes()),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_signature!(algorithm, into_typed_pk)
    }

    /// Converts the raw key bytes into a typed key agreement public key.
    ///
    /// 将原始密钥字节转换为类型化的密钥协商公钥。
    #[cfg(feature = "asymmetric-key-agreement")]
    pub fn into_key_agreement_typed(
        self,
        algorithm: KeyAgreementAlgorithm,
    ) -> Result<key_agreement::TypedKeyAgreementPublicKey, Error> {
        use key_agreement::TypedKeyAgreementPublicKey;
        macro_rules! into_typed_pk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let pk = <KT as AsymmetricKeySet>::PublicKey::from_bytes(self.as_bytes())?;
                Ok(TypedKeyAgreementPublicKey {
                    key: AsymmetricPublicKey::new(pk.to_bytes()),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_key_agreement!(algorithm, into_typed_pk)
    }
}


/// A trait for typed asymmetric keys.
///
/// 类型化非对称密钥的 trait。
pub trait TypedAsymmetricKeyTrait: AsRef<[u8]> {
    /// The algorithm enum.
    ///
    /// 算法枚举。
    type Algorithm: Copy;

    /// Returns the algorithm of the key.
    ///
    /// 返回密钥的算法。
    fn algorithm(&self) -> Self::Algorithm;
}

pub trait TypedAsymmetricPublicKeyTrait: TypedAsymmetricKeyTrait {
    fn to_bytes(&self) -> Vec<u8>;
    fn untyped(&self) -> AsymmetricPublicKey;
    fn as_bytes(&self) -> &[u8];
    fn into_bytes(self) -> ::seal_crypto::zeroize::Zeroizing<Vec<u8>>;
}

pub trait TypedAsymmetricPrivateKeyTrait: TypedAsymmetricKeyTrait {
    fn to_bytes(&self) -> Vec<u8>;
    fn untyped(&self) -> AsymmetricPrivateKey;
    fn as_bytes(&self) -> &[u8];
    fn into_bytes(self) -> ::seal_crypto::zeroize::Zeroizing<Vec<u8>>;
}

#[macro_export(local_inner_macros)]
macro_rules! impl_typed_asymmetric_private_key {
    ($typed_key:ident, $alg_type:ty) => {
        impl $crate::keys::asymmetric::TypedAsymmetricPrivateKeyTrait for $typed_key {
            fn to_bytes(&self) -> Vec<u8> {
                self.key.to_bytes()
            }

            fn untyped(&self) -> AsymmetricPrivateKey {
                self.key.clone()
            }

            fn as_bytes(&self) -> &[u8] {
                self.key.as_bytes()
            }

            fn into_bytes(self) -> ::seal_crypto::zeroize::Zeroizing<Vec<u8>> {
                self.key.into_bytes()
            }
        }

        impl AsRef<[u8]> for $typed_key {
            fn as_ref(&self) -> &[u8] {
                self.key.as_bytes()
            }
        }

        impl $crate::keys::asymmetric::TypedAsymmetricKeyTrait for $typed_key {
            type Algorithm = $alg_type;

            fn algorithm(&self) -> Self::Algorithm {
                self.algorithm
            }
        }
    };
}

#[macro_export(local_inner_macros)]
macro_rules! impl_typed_asymmetric_public_key {
    ($typed_key:ident, $alg_type:ty) => {
        impl $crate::keys::asymmetric::TypedAsymmetricPublicKeyTrait for $typed_key {
            fn to_bytes(&self) -> Vec<u8> {
                self.key.to_bytes()
            }

            fn untyped(&self) -> AsymmetricPublicKey {
                self.key.clone()
            }

            fn as_bytes(&self) -> &[u8] {
                self.key.as_bytes()
            }

            fn into_bytes(self) -> ::seal_crypto::zeroize::Zeroizing<Vec<u8>> {
                self.key.into_bytes()
            }
        }

        impl AsRef<[u8]> for $typed_key {
            fn as_ref(&self) -> &[u8] {
                self.key.as_bytes()
            }
        }

        impl $crate::keys::asymmetric::TypedAsymmetricKeyTrait for $typed_key {
            type Algorithm = $alg_type;

            fn algorithm(&self) -> Self::Algorithm {
                self.algorithm
            }
        }
    };
}