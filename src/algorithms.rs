
use bincode::{Decode, Encode};

///
/// 对称加密算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum SymmetricAlgorithm {
    AesGcm(AesKeySize),
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum AesKeySize {
    K128,
    K256,
}

impl SymmetricAlgorithm {
    pub fn build() -> SymmetricAlgorithmBuilder {
        SymmetricAlgorithmBuilder
    }
}

pub struct SymmetricAlgorithmBuilder;

impl SymmetricAlgorithmBuilder {
    pub fn aes128_gcm(self) -> SymmetricAlgorithm {
        SymmetricAlgorithm::AesGcm(AesKeySize::K128)
    }
    pub fn aes256_gcm(self) -> SymmetricAlgorithm {
        SymmetricAlgorithm::AesGcm(AesKeySize::K256)
    }
    pub fn chacha20_poly1305(self) -> SymmetricAlgorithm {
        SymmetricAlgorithm::ChaCha20Poly1305
    }
    pub fn xchacha20_poly1305(self) -> SymmetricAlgorithm {
        SymmetricAlgorithm::XChaCha20Poly1305
    }
}


use crate::wrappers::symmetric::SymmetricAlgorithmWrapper;
impl SymmetricAlgorithm {
    pub fn into_symmetric_wrapper(self) -> SymmetricAlgorithmWrapper {
        use crate::wrappers::symmetric::{
            Aes128GcmWrapper, Aes256GcmWrapper, ChaCha20Poly1305Wrapper, XChaCha20Poly1305Wrapper,
        };
        match self {
            SymmetricAlgorithm::AesGcm(AesKeySize::K128) => {
                SymmetricAlgorithmWrapper::new(Box::new(Aes128GcmWrapper::default()))
            }
            SymmetricAlgorithm::AesGcm(AesKeySize::K256) => {
                SymmetricAlgorithmWrapper::new(Box::new(Aes256GcmWrapper::default()))
            }
            SymmetricAlgorithm::ChaCha20Poly1305 => {
                SymmetricAlgorithmWrapper::new(Box::new(ChaCha20Poly1305Wrapper::default()))
            }
            SymmetricAlgorithm::XChaCha20Poly1305 => {
                SymmetricAlgorithmWrapper::new(Box::new(XChaCha20Poly1305Wrapper::default()))
            }
        }
    }
}

/// Asymmetric encryption algorithm enum.
///
/// 非对称加密算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum AsymmetricAlgorithm {
    Rsa(RsaBits, HashAlgorithmEnum),
    Kyber(KyberSecurityLevel),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum RsaBits {
    B2048,
    B4096,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum KyberSecurityLevel {
    L512,
    L768,
    L1024,
}

pub struct AsymmetricAlgorithmBuilder;

impl AsymmetricAlgorithmBuilder {
    pub fn rsa2048(self) -> RsaBuilder {
        RsaBuilder { bits: RsaBits::B2048 }
    }

    pub fn rsa4096(self) -> RsaBuilder {
        RsaBuilder { bits: RsaBits::B4096 }
    }

    pub fn kyber512(self) -> AsymmetricAlgorithm {
        AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L512)
    }

    pub fn kyber768(self) -> AsymmetricAlgorithm {
        AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L768)
    }

    pub fn kyber1024(self) -> AsymmetricAlgorithm {
        AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L1024)
    }
}

pub struct RsaBuilder {
    bits: RsaBits,
}

impl RsaBuilder {
    pub fn sha256(self) -> AsymmetricAlgorithm {
        AsymmetricAlgorithm::Rsa(self.bits, HashAlgorithmEnum::Sha256)
    }

    pub fn sha384(self) -> AsymmetricAlgorithm {
        AsymmetricAlgorithm::Rsa(self.bits, HashAlgorithmEnum::Sha384)
    }

    pub fn sha512(self) -> AsymmetricAlgorithm {
        AsymmetricAlgorithm::Rsa(self.bits, HashAlgorithmEnum::Sha512)
    }
}

impl AsymmetricAlgorithm {
    pub fn build() -> AsymmetricAlgorithmBuilder {
        AsymmetricAlgorithmBuilder
    }
}


use crate::wrappers::asymmetric::AsymmetricAlgorithmWrapper;
impl AsymmetricAlgorithm {
    pub fn into_asymmetric_wrapper(self) -> AsymmetricAlgorithmWrapper {
        use crate::wrappers::asymmetric::{
            Kyber1024Wrapper, Kyber512Wrapper, Kyber768Wrapper, 
            Rsa2048Sha256Wrapper, Rsa2048Sha384Wrapper, Rsa2048Sha512Wrapper,
            Rsa4096Sha256Wrapper, Rsa4096Sha384Wrapper, Rsa4096Sha512Wrapper,
        };
        match self {
            AsymmetricAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha256) => {
                AsymmetricAlgorithmWrapper::new(Box::new(Rsa2048Sha256Wrapper::default()))
            }
            AsymmetricAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha384) => {
                AsymmetricAlgorithmWrapper::new(Box::new(Rsa2048Sha384Wrapper::default()))
            }
            AsymmetricAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha512) => {
                AsymmetricAlgorithmWrapper::new(Box::new(Rsa2048Sha512Wrapper::default()))
            }
            AsymmetricAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha256) => {
                AsymmetricAlgorithmWrapper::new(Box::new(Rsa4096Sha256Wrapper::default()))
            }
            AsymmetricAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha384) => {
                AsymmetricAlgorithmWrapper::new(Box::new(Rsa4096Sha384Wrapper::default()))
            }
            AsymmetricAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha512) => {
                AsymmetricAlgorithmWrapper::new(Box::new(Rsa4096Sha512Wrapper::default()))
            }
            AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L512) => {
                AsymmetricAlgorithmWrapper::new(Box::new(Kyber512Wrapper::default()))
            }
            AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L768) => {
                AsymmetricAlgorithmWrapper::new(Box::new(Kyber768Wrapper::default()))
            }
            AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L1024) => {
                AsymmetricAlgorithmWrapper::new(Box::new(Kyber1024Wrapper::default()))
            }
        }
    }
}

/// Digital signature algorithm enum.
///
/// 数字签名算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum SignatureAlgorithm {
    Dilithium(DilithiumSecurityLevel),
    Ed25519,
    EcdsaP256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum DilithiumSecurityLevel {
    L2,
    L3,
    L5,
}

impl SignatureAlgorithm {
    pub fn build() -> SignatureAlgorithmBuilder {
        SignatureAlgorithmBuilder
    }
}

pub struct SignatureAlgorithmBuilder;

impl SignatureAlgorithmBuilder {
    pub fn dilithium2(self) -> SignatureAlgorithm {
        SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L2)
    }
    pub fn dilithium3(self) -> SignatureAlgorithm {
        SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L3)
    }
    pub fn dilithium5(self) -> SignatureAlgorithm {
        SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L5)
    }
    pub fn ed25519(self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }
    pub fn ecdsa_p256(self) -> SignatureAlgorithm {
        SignatureAlgorithm::EcdsaP256
    }
}

use crate::wrappers::signature::SignatureAlgorithmWrapper;

impl SignatureAlgorithm {
    pub fn into_signature_wrapper(self) -> SignatureAlgorithmWrapper {
        use crate::wrappers::signature::{
            Dilithium2Wrapper, Dilithium3Wrapper, Dilithium5Wrapper, EcdsaP256Wrapper,
            Ed25519Wrapper,
        };
        match self {
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L2) => {
                SignatureAlgorithmWrapper::new(Box::new(Dilithium2Wrapper::default()))
            }
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L3) => {
                SignatureAlgorithmWrapper::new(Box::new(Dilithium3Wrapper::default()))
            }
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L5) => {
                SignatureAlgorithmWrapper::new(Box::new(Dilithium5Wrapper::default()))
            }
            SignatureAlgorithm::Ed25519 => {
                SignatureAlgorithmWrapper::new(Box::new(Ed25519Wrapper::default()))
            }
            SignatureAlgorithm::EcdsaP256 => {
                SignatureAlgorithmWrapper::new(Box::new(EcdsaP256Wrapper::default()))
            }
        }
    }
}

///
/// 密钥派生函数 (KDF) 算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum KdfKeyAlgorithm {
    Hkdf(HashAlgorithmEnum),
}

impl KdfKeyAlgorithm {
    pub fn build() -> KdfKeyAlgorithmBuilder {
        KdfKeyAlgorithmBuilder
    }
}

pub struct KdfKeyAlgorithmBuilder;

impl KdfKeyAlgorithmBuilder {
    pub fn hkdf_sha256(self) -> KdfKeyAlgorithm {
        KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha256)
    }
    pub fn hkdf_sha384(self) -> KdfKeyAlgorithm {
        KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha384)
    }
    pub fn hkdf_sha512(self) -> KdfKeyAlgorithm {
        KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha512)
    }
}

use crate::wrappers::kdf::key::KdfKeyWrapper;

impl KdfKeyAlgorithm {
    pub fn into_kdf_key_wrapper(self) -> KdfKeyWrapper {
        use crate::wrappers::kdf::key::{
            HkdfSha256Wrapper, HkdfSha384Wrapper, HkdfSha512Wrapper,
        };
        match self {
            KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha256) => {
                KdfKeyWrapper::new(Box::new(HkdfSha256Wrapper::default()))
            }
            KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha384) => {
                KdfKeyWrapper::new(Box::new(HkdfSha384Wrapper::default()))
            }
            KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha512) => {
                KdfKeyWrapper::new(Box::new(HkdfSha512Wrapper::default()))
            }
        }
    }
}

///
/// 基于密码的 KDF 算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum KdfPasswordAlgorithm {
    Argon2,
    Pbkdf2(HashAlgorithmEnum),
}

impl KdfPasswordAlgorithm {
    pub fn build() -> KdfPasswordAlgorithmBuilder {
        KdfPasswordAlgorithmBuilder
    }
}

pub struct KdfPasswordAlgorithmBuilder;

impl KdfPasswordAlgorithmBuilder {
    pub fn argon2(self) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Argon2
    }
    pub fn pbkdf2_sha256(self) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2(HashAlgorithmEnum::Sha256)
    }
    pub fn pbkdf2_sha384(self) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2(HashAlgorithmEnum::Sha384)
    }
    pub fn pbkdf2_sha512(self) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2(HashAlgorithmEnum::Sha512)
    }
}

use crate::wrappers::kdf::passwd::KdfPasswordWrapper;

impl KdfPasswordAlgorithm {
    pub fn into_kdf_password_wrapper(self) -> KdfPasswordWrapper {
        use crate::wrappers::kdf::passwd::{
            Argon2Wrapper, Pbkdf2Sha256Wrapper, Pbkdf2Sha384Wrapper, Pbkdf2Sha512Wrapper,
        };
        match self {
            KdfPasswordAlgorithm::Argon2 => {
                KdfPasswordWrapper::new(Box::new(Argon2Wrapper::default()))
            }
            KdfPasswordAlgorithm::Pbkdf2(HashAlgorithmEnum::Sha256) => {
                KdfPasswordWrapper::new(Box::new(Pbkdf2Sha256Wrapper::default()))
            }
            KdfPasswordAlgorithm::Pbkdf2(HashAlgorithmEnum::Sha384) => {
                KdfPasswordWrapper::new(Box::new(Pbkdf2Sha384Wrapper::default()))
            }
            KdfPasswordAlgorithm::Pbkdf2(HashAlgorithmEnum::Sha512) => {
                KdfPasswordWrapper::new(Box::new(Pbkdf2Sha512Wrapper::default()))
            }
        }
    }
}

///
/// 可扩展输出函数 (XOF) 算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum XofAlgorithm {
    Shake(ShakeVariant),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum ShakeVariant {
    V128,
    V256,
}

impl XofAlgorithm {
    pub fn build() -> XofAlgorithmBuilder {
        XofAlgorithmBuilder
    }
}

pub struct XofAlgorithmBuilder;

impl XofAlgorithmBuilder {
    pub fn shake128(self) -> XofAlgorithm {
        XofAlgorithm::Shake(ShakeVariant::V128)
    }
    pub fn shake256(self) -> XofAlgorithm {
        XofAlgorithm::Shake(ShakeVariant::V256)
    }
}

use crate::wrappers::xof::XofWrapper;

impl XofAlgorithm {
    pub fn into_xof_wrapper(self) -> XofWrapper {
        use crate::wrappers::xof::{Shake128Wrapper, Shake256Wrapper};
        match self {
            XofAlgorithm::Shake(ShakeVariant::V128) => XofWrapper::new(Box::new(Shake128Wrapper::default())),
            XofAlgorithm::Shake(ShakeVariant::V256) => XofWrapper::new(Box::new(Shake256Wrapper::default())),
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum HashAlgorithmEnum {
    Sha256,
    Sha384,
    Sha512,
}