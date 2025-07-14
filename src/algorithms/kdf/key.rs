use bincode::{Decode, Encode};
use crate::algorithms::HashAlgorithmEnum;

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
