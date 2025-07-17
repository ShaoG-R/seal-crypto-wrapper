

#[cfg(feature = "asymmetric-kem")]
pub mod signature;

#[cfg(feature = "asymmetric-kem")]
pub mod kem;

#[cfg(feature = "asymmetric-key-agreement")]
pub mod key_agreement;

#[cfg(feature = "asymmetric-kem")]
use self::kem::KemAlgorithm;
#[cfg(feature = "asymmetric-signature")]
use self::signature::SignatureAlgorithm;

/// Asymmetric algorithm enum.
///
/// 非对称算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AsymmetricAlgorithm {
    #[cfg(feature = "asymmetric-kem")]
    Kem(KemAlgorithm),
    #[cfg(feature = "asymmetric-signature")]
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
    #[cfg(feature = "asymmetric-kem")]
    pub fn kem(self) -> kem::KemAlgorithmBuilder {
        kem::KemAlgorithm::build()
    }

    /// Create a new signature algorithm builder.
    ///
    /// 创建一个新的数字签名算法构建器。
    #[cfg(feature = "asymmetric-signature")]
    pub fn signature(self) -> signature::SignatureAlgorithmBuilder {
        signature::SignatureAlgorithm::build()
    }

    /// Create a new key agreement algorithm builder.
    ///
    /// 创建一个新的密钥协商算法构建器。
    #[cfg(feature = "asymmetric-key-agreement")]
    pub fn key_agreement(self) -> key_agreement::KeyAgreementAlgorithmBuilder {
        key_agreement::KeyAgreementAlgorithm::build()
    }
}