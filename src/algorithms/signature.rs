use bincode::{Decode, Encode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum DilithiumSecurityLevel {
    L2,
    L3,
    L5,
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
