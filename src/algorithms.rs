
use bincode::{Decode, Encode};

/// Symmetric encryption algorithm enum.
///
/// 对称加密算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum SymmetricAlgorithmEnum {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

use crate::wrappers::symmetric::SymmetricAlgorithmWrapper;
impl SymmetricAlgorithmEnum {
    pub fn into_symmetric_wrapper(self) -> SymmetricAlgorithmWrapper {
        use crate::wrappers::symmetric::{
            Aes128GcmWrapper, Aes256GcmWrapper, ChaCha20Poly1305Wrapper, XChaCha20Poly1305Wrapper,
        };
        match self {
            SymmetricAlgorithmEnum::Aes128Gcm => {
                SymmetricAlgorithmWrapper::new(Box::new(Aes128GcmWrapper::default()))
            }
            SymmetricAlgorithmEnum::Aes256Gcm => {
                SymmetricAlgorithmWrapper::new(Box::new(Aes256GcmWrapper::default()))
            }
            SymmetricAlgorithmEnum::ChaCha20Poly1305 => {
                SymmetricAlgorithmWrapper::new(Box::new(ChaCha20Poly1305Wrapper::default()))
            }
            SymmetricAlgorithmEnum::XChaCha20Poly1305 => {
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
pub enum AsymmetricAlgorithmEnum {
    Rsa2048Sha256,
    Rsa4096Sha256,
    Kyber512,
    Kyber768,
    Kyber1024,
}

use crate::wrappers::asymmetric::AsymmetricAlgorithmWrapper;
impl AsymmetricAlgorithmEnum {
    pub fn into_asymmetric_wrapper(self) -> AsymmetricAlgorithmWrapper {
        use crate::wrappers::asymmetric::{
            Kyber1024Wrapper, Kyber512Wrapper, Kyber768Wrapper, Rsa2048Sha256Wrapper,
            Rsa4096Sha256Wrapper,
        };
        match self {
            AsymmetricAlgorithmEnum::Rsa2048Sha256 => {
                AsymmetricAlgorithmWrapper::new(Box::new(Rsa2048Sha256Wrapper::default()))
            }
            AsymmetricAlgorithmEnum::Rsa4096Sha256 => {
                AsymmetricAlgorithmWrapper::new(Box::new(Rsa4096Sha256Wrapper::default()))
            }
            AsymmetricAlgorithmEnum::Kyber512 => {
                AsymmetricAlgorithmWrapper::new(Box::new(Kyber512Wrapper::default()))
            }
            AsymmetricAlgorithmEnum::Kyber768 => {
                AsymmetricAlgorithmWrapper::new(Box::new(Kyber768Wrapper::default()))
            }
            AsymmetricAlgorithmEnum::Kyber1024 => {
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
pub enum SignatureAlgorithmEnum {
    Dilithium2,
    Dilithium3,
    Dilithium5,
    Ed25519,
    EcdsaP256,
}

use crate::wrappers::signature::SignatureAlgorithmWrapper;

impl SignatureAlgorithmEnum {
    pub fn into_signature_wrapper(self) -> SignatureAlgorithmWrapper {
        use crate::wrappers::signature::{
            Dilithium2Wrapper, Dilithium3Wrapper, Dilithium5Wrapper, EcdsaP256Wrapper,
            Ed25519Wrapper,
        };
        match self {
            SignatureAlgorithmEnum::Dilithium2 => {
                SignatureAlgorithmWrapper::new(Box::new(Dilithium2Wrapper::default()))
            }
            SignatureAlgorithmEnum::Dilithium3 => {
                SignatureAlgorithmWrapper::new(Box::new(Dilithium3Wrapper::default()))
            }
            SignatureAlgorithmEnum::Dilithium5 => {
                SignatureAlgorithmWrapper::new(Box::new(Dilithium5Wrapper::default()))
            }
            SignatureAlgorithmEnum::Ed25519 => {
                SignatureAlgorithmWrapper::new(Box::new(Ed25519Wrapper::default()))
            }
            SignatureAlgorithmEnum::EcdsaP256 => {
                SignatureAlgorithmWrapper::new(Box::new(EcdsaP256Wrapper::default()))
            }
        }
    }
}

/// Key Derivation Function (KDF) algorithm enum.
///
/// 密钥派生函数 (KDF) 算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum KdfKeyAlgorithmEnum {
    HkdfSha256,
    HkdfSha384,
    HkdfSha512,
}

use crate::wrappers::kdf::key::KdfKeyWrapper;

impl KdfKeyAlgorithmEnum {
    pub fn into_kdf_key_wrapper(self) -> KdfKeyWrapper {
        use crate::wrappers::kdf::key::{
            HkdfSha256Wrapper, HkdfSha384Wrapper, HkdfSha512Wrapper,
        };
        match self {
            KdfKeyAlgorithmEnum::HkdfSha256 => {
                KdfKeyWrapper::new(Box::new(HkdfSha256Wrapper::default()))
            }
            KdfKeyAlgorithmEnum::HkdfSha384 => {
                KdfKeyWrapper::new(Box::new(HkdfSha384Wrapper::default()))
            }
            KdfKeyAlgorithmEnum::HkdfSha512 => {
                KdfKeyWrapper::new(Box::new(HkdfSha512Wrapper::default()))
            }
        }
    }
}

/// Password-based KDF algorithm enum.
///
/// 基于密码的 KDF 算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum KdfPasswordAlgorithmEnum {
    Argon2,
    Pbkdf2Sha256,
    Pbkdf2Sha384,
    Pbkdf2Sha512,
}

use crate::wrappers::kdf::passwd::KdfPasswordWrapper;

impl KdfPasswordAlgorithmEnum {
    pub fn into_kdf_password_wrapper(self) -> KdfPasswordWrapper {
        use crate::wrappers::kdf::passwd::{
            Argon2Wrapper, Pbkdf2Sha256Wrapper, Pbkdf2Sha384Wrapper, Pbkdf2Sha512Wrapper,
        };
        match self {
            KdfPasswordAlgorithmEnum::Argon2 => {
                KdfPasswordWrapper::new(Box::new(Argon2Wrapper::default()))
            }
            KdfPasswordAlgorithmEnum::Pbkdf2Sha256 => {
                KdfPasswordWrapper::new(Box::new(Pbkdf2Sha256Wrapper::default()))
            }
            KdfPasswordAlgorithmEnum::Pbkdf2Sha384 => {
                KdfPasswordWrapper::new(Box::new(Pbkdf2Sha384Wrapper::default()))
            }
            KdfPasswordAlgorithmEnum::Pbkdf2Sha512 => {
                KdfPasswordWrapper::new(Box::new(Pbkdf2Sha512Wrapper::default()))
            }
        }
    }
}

/// Extendable-Output Function (XOF) algorithm enum.
///
/// 可扩展输出函数 (XOF) 算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum XofAlgorithmEnum {
    Shake128,
    Shake256,
}

use crate::wrappers::xof::XofWrapper;

impl XofAlgorithmEnum {
    pub fn into_xof_wrapper(self) -> XofWrapper {
        use crate::wrappers::xof::{Shake128Wrapper, Shake256Wrapper};
        match self {
            XofAlgorithmEnum::Shake128 => XofWrapper::new(Box::new(Shake128Wrapper::default())),
            XofAlgorithmEnum::Shake256 => XofWrapper::new(Box::new(Shake256Wrapper::default())),
        }
    }
}
