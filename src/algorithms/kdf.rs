pub mod key;
pub mod passwd;

use self::{key::KdfKeyAlgorithm, passwd::KdfPasswordAlgorithm};

/// Key derivation function algorithm enum.
///
/// 密钥派生函数算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KdfAlgorithm {
    Key(KdfKeyAlgorithm),
    Password(KdfPasswordAlgorithm),
}

impl KdfAlgorithm {
    /// Create a new KDF algorithm builder.
    ///
    /// 创建一个新的 KDF 算法构建器。
    pub fn build() -> KdfAlgorithmBuilder {
        KdfAlgorithmBuilder
    }
}

pub struct KdfAlgorithmBuilder;

impl KdfAlgorithmBuilder {
    /// Create a new KDF key algorithm builder.
    ///
    /// 创建一个新的 KDF 密钥算法构建器。
    pub fn key(self) -> key::KdfKeyAlgorithmBuilder {
        key::KdfKeyAlgorithm::build()
    }

    /// Create a new KDF password algorithm builder.
    ///
    /// 创建一个新的 KDF 密码算法构建器。
    pub fn passwd(self) -> passwd::KdfPasswordAlgorithmBuilder {
        passwd::KdfPasswordAlgorithm::build()
    }
}
