use bincode::{Decode, Encode};
use crate::algorithms::HashAlgorithmEnum;

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
