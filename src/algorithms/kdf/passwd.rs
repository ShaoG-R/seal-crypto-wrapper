use crate::algorithms::HashAlgorithmEnum;
use bincode::{Decode, Encode};


#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, serde::Serialize, serde::Deserialize,
)]
pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

///
/// 基于密码的 KDF 算法枚举。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, serde::Serialize, serde::Deserialize,
)]
pub enum KdfPasswordAlgorithm {
    Argon2(Option<Argon2Params>),
    Pbkdf2 {
        hash: HashAlgorithmEnum,
        c: Option<u32>,
    },
}

impl KdfPasswordAlgorithm {
    pub fn build() -> KdfPasswordAlgorithmBuilder {
        KdfPasswordAlgorithmBuilder
    }
}

pub struct KdfPasswordAlgorithmBuilder;

impl KdfPasswordAlgorithmBuilder {
    pub fn argon2_default(self) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Argon2(None)
    }

    pub fn pbkdf2_sha256_default(self) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2 {
            hash: HashAlgorithmEnum::Sha256,
            c: None,
        }
    }

    pub fn pbkdf2_sha384_default(self) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2 {
            hash: HashAlgorithmEnum::Sha384,
            c: None,
        }
    }

    pub fn pbkdf2_sha512_default(self) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2 {
            hash: HashAlgorithmEnum::Sha512,
            c: None,
        }
    }

    pub fn argon2_with_params(self, m_cost: u32, t_cost: u32, p_cost: u32) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Argon2(Some(Argon2Params {
            m_cost,
            t_cost,
            p_cost,
        }))
    }

    pub fn pbkdf2_sha256_with_params(self, c: u32) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2 {
            hash: HashAlgorithmEnum::Sha256,
            c: Some(c),
        }
    }

    pub fn pbkdf2_sha384_with_params(self, c: u32) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2 {
            hash: HashAlgorithmEnum::Sha384,
            c: Some(c),
        }
    }

    pub fn pbkdf2_sha512_with_params(self, c: u32) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2 {
            hash: HashAlgorithmEnum::Sha512,
            c: Some(c),
        }
    }
}

use crate::wrappers::kdf::passwd::KdfPasswordWrapper;

impl KdfPasswordAlgorithm {
    pub fn into_kdf_password_wrapper(self) -> KdfPasswordWrapper {
        use crate::wrappers::kdf::passwd::{
            Argon2Wrapper, Pbkdf2Sha256Wrapper, Pbkdf2Sha384Wrapper, Pbkdf2Sha512Wrapper,
        };
        match self {
            KdfPasswordAlgorithm::Argon2(Some(params)) => {
                KdfPasswordWrapper::new(Box::new(Argon2Wrapper::new(params.m_cost, params.t_cost, params.p_cost)))
            }
            KdfPasswordAlgorithm::Argon2(None) => {
                KdfPasswordWrapper::new(Box::new(Argon2Wrapper::default()))
            }
            KdfPasswordAlgorithm::Pbkdf2 { hash, c } => {
                match (hash, c) {
                    (HashAlgorithmEnum::Sha256, Some(c)) => {
                        KdfPasswordWrapper::new(Box::new(Pbkdf2Sha256Wrapper::new(c)))
                    }
                    (HashAlgorithmEnum::Sha384, Some(c)) => {
                        KdfPasswordWrapper::new(Box::new(Pbkdf2Sha384Wrapper::new(c)))
                    }
                    (HashAlgorithmEnum::Sha512, Some(c)) => {
                        KdfPasswordWrapper::new(Box::new(Pbkdf2Sha512Wrapper::new(c)))
                    }
                    (HashAlgorithmEnum::Sha256, None) => {
                        KdfPasswordWrapper::new(Box::new(Pbkdf2Sha256Wrapper::default()))
                    }
                    (HashAlgorithmEnum::Sha384, None) => {
                        KdfPasswordWrapper::new(Box::new(Pbkdf2Sha384Wrapper::default()))
                    }
                    (HashAlgorithmEnum::Sha512, None) => {
                        KdfPasswordWrapper::new(Box::new(Pbkdf2Sha512Wrapper::default()))
                    }
                }
            }
        }
    }
}
