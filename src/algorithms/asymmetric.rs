use bincode::{Decode, Encode};
use crate::algorithms::HashAlgorithmEnum;


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