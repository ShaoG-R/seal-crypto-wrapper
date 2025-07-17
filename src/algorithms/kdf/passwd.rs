use crate::algorithms::HashAlgorithmEnum;
use bincode::{Decode, Encode};

///
/// 基于密码的 KDF 算法枚举。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, serde::Serialize, serde::Deserialize,
)]
pub enum KdfPasswordAlgorithm {
    Argon2 {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    },
    Pbkdf2 {
        hash: HashAlgorithmEnum,
        c: u32,
    },
}

impl KdfPasswordAlgorithm {
    pub fn build() -> KdfPasswordAlgorithmBuilder {
        KdfPasswordAlgorithmBuilder
    }
}

pub struct KdfPasswordAlgorithmBuilder;

impl KdfPasswordAlgorithmBuilder {
    pub fn argon2(self, m_cost: u32, t_cost: u32, p_cost: u32) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Argon2 { m_cost, t_cost, p_cost }
    }
    pub fn pbkdf2_sha256(self, c: u32) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2 { hash: HashAlgorithmEnum::Sha256, c }
    }
    pub fn pbkdf2_sha384(self, c: u32) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2 { hash: HashAlgorithmEnum::Sha384, c }
    }
    pub fn pbkdf2_sha512(self, c: u32) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2 { hash: HashAlgorithmEnum::Sha512, c }
    }
}

use crate::wrappers::kdf::passwd::KdfPasswordWrapper;

impl KdfPasswordAlgorithm {
    pub fn into_kdf_password_wrapper(self) -> KdfPasswordWrapper {
        use crate::wrappers::kdf::passwd::{
            Argon2Wrapper, Pbkdf2Sha256Wrapper, Pbkdf2Sha384Wrapper, Pbkdf2Sha512Wrapper,
        };
        match self {
            KdfPasswordAlgorithm::Argon2 { m_cost, t_cost, p_cost } => {
                KdfPasswordWrapper::new(Box::new(Argon2Wrapper::new(m_cost, t_cost, p_cost)))
            }
            KdfPasswordAlgorithm::Pbkdf2 { hash, c } => {
                match hash {
                    HashAlgorithmEnum::Sha256 => {
                        KdfPasswordWrapper::new(Box::new(Pbkdf2Sha256Wrapper::new(c)))
                    }
                    HashAlgorithmEnum::Sha384 => {
                        KdfPasswordWrapper::new(Box::new(Pbkdf2Sha384Wrapper::new(c)))
                    }
                    HashAlgorithmEnum::Sha512 => {
                        KdfPasswordWrapper::new(Box::new(Pbkdf2Sha512Wrapper::new(c)))
                    }
                }
            }
        }
    }
}
