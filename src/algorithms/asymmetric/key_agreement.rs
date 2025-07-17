use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Key agreement algorithm enum.
///
/// 密钥协商算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, Serialize, Deserialize)]
pub enum KeyAgreementAlgorithm {
    EcdhP256,
}

impl KeyAgreementAlgorithm {
    pub fn build() -> KeyAgreementAlgorithmBuilder {
        KeyAgreementAlgorithmBuilder
    }
}

pub struct KeyAgreementAlgorithmBuilder;

impl KeyAgreementAlgorithmBuilder {
    pub fn ecdh_p256(self) -> KeyAgreementAlgorithm {
        KeyAgreementAlgorithm::EcdhP256
    }
}

use crate::wrappers::asymmetric::key_agreement::KeyAgreementAlgorithmWrapper;

impl KeyAgreementAlgorithm {
    pub fn into_key_agreement_wrapper(self) -> KeyAgreementAlgorithmWrapper {
        use crate::wrappers::asymmetric::key_agreement::EcdhP256Wrapper;
        match self {
            KeyAgreementAlgorithm::EcdhP256 => {
                KeyAgreementAlgorithmWrapper::new(Box::new(EcdhP256Wrapper::default()))
            }
        }
    }
}
