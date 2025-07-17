

#[cfg(feature = "signature")]
pub mod signature;

#[cfg(feature = "kem")]
pub mod kem;

#[cfg(feature = "kem")]
use self::kem::KemAlgorithm;
#[cfg(feature = "signature")]
use self::signature::SignatureAlgorithm;

/// Asymmetric algorithm enum.
///
/// 非对称算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AsymmetricAlgorithm {
    #[cfg(feature = "kem")]
    Kem(KemAlgorithm),
    #[cfg(feature = "signature")]
    Signature(SignatureAlgorithm),
}

impl AsymmetricAlgorithm {
    /// Create a new asymmetric algorithm builder.
    ///
    /// 创建一个新的非对称算法构建器。
    pub fn build() -> AsymmetricAlgorithmBuilder {
        AsymmetricAlgorithmBuilder
    }
}

pub struct AsymmetricAlgorithmBuilder;

impl AsymmetricAlgorithmBuilder {
    /// Create a new KEM algorithm builder.
    ///
    /// 创建一个新的 KEM 算法构建器。
    #[cfg(feature = "kem")]
    pub fn kem(self) -> kem::KemAlgorithmBuilder {
        kem::KemAlgorithm::build()
    }

    /// Create a new signature algorithm builder.
    ///
    /// 创建一个新的数字签名算法构建器。
    #[cfg(feature = "signature")]
    pub fn signature(self) -> signature::SignatureAlgorithmBuilder {
        signature::SignatureAlgorithm::build()
    }
}