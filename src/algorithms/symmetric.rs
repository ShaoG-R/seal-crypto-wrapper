
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
