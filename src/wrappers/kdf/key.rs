use crate::algorithms::HashAlgorithmEnum;
use crate::algorithms::kdf::key::KdfKeyAlgorithm;
use crate::error::{Error, Result};
use crate::traits::KdfKeyAlgorithmTrait;
use seal_crypto::prelude::KeyBasedDerivation;
use seal_crypto::schemes::kdf::hkdf::{HkdfSha256, HkdfSha384, HkdfSha512};
use seal_crypto::zeroize::Zeroizing;
use crate::define_wrapper;
use std::ops::Deref;

macro_rules! impl_kdf_key_algorithm {
    ($wrapper:ident, $algo:ty, $algo_enum:expr) => {
        define_wrapper!(@struct_with_algorithm_default, $wrapper, $algo, KdfKeyAlgorithmTrait, {
            fn derive(
                &self,
                ikm: &[u8],
                salt: Option<&[u8]>,
                info: Option<&[u8]>,
                output_len: usize,
            ) -> Result<Zeroizing<Vec<u8>>> {
                self.algorithm
                    .derive(ikm, salt, info, output_len)
                    .map(|k| k.0)
                    .map_err(Error::from)
            }

            fn algorithm(&self) -> KdfKeyAlgorithm {
                $algo_enum
            }

            fn clone_box(&self) -> Box<dyn KdfKeyAlgorithmTrait> {
                Box::new(self.clone())
            }
        });
    };
}

impl_kdf_key_algorithm!(
    HkdfSha256Wrapper,
    HkdfSha256,
    KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha256)
);

impl_kdf_key_algorithm!(
    HkdfSha384Wrapper,
    HkdfSha384,
    KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha384)
);

impl_kdf_key_algorithm!(
    HkdfSha512Wrapper,
    HkdfSha512,
    KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha512)
);

#[derive(Clone)]
pub struct KdfKeyWrapper {
    algorithm: Box<dyn KdfKeyAlgorithmTrait>,
}

impl KdfKeyAlgorithmTrait for KdfKeyWrapper {
    fn derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.algorithm.derive(ikm, salt, info, output_len)
    }

    fn algorithm(&self) -> KdfKeyAlgorithm {
        self.algorithm.algorithm()
    }

    fn clone_box(&self) -> Box<dyn KdfKeyAlgorithmTrait> {
        self.algorithm.clone_box()
    }
}

impl KdfKeyWrapper {
    pub fn new(algorithm: Box<dyn KdfKeyAlgorithmTrait>) -> Self {
        Self { algorithm }
    }

    pub fn from_enum(algorithm: KdfKeyAlgorithm) -> Self {
        let algorithm: Box<dyn KdfKeyAlgorithmTrait> = match algorithm {
            KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha256) => Box::new(HkdfSha256Wrapper::default()),
            KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha384) => Box::new(HkdfSha384Wrapper::default()),
            KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha512) => Box::new(HkdfSha512Wrapper::default()),
        };
        Self::new(algorithm)
    }
}

impl Deref for KdfKeyWrapper {
    type Target = Box<dyn KdfKeyAlgorithmTrait>;

    fn deref(&self) -> &Self::Target {
        &self.algorithm
    }
}

impl From<KdfKeyAlgorithm> for KdfKeyWrapper {
    fn from(algorithm: KdfKeyAlgorithm) -> Self {
        Self::from_enum(algorithm)
    }
}

impl From<Box<dyn KdfKeyAlgorithmTrait>> for KdfKeyWrapper {
    fn from(algorithm: Box<dyn KdfKeyAlgorithmTrait>) -> Self {
        Self::new(algorithm)
    }
}
