use bincode::{Decode, Encode};

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