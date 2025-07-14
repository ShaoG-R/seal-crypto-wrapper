use crate::algorithms::{HashAlgorithmEnum, KdfKeyAlgorithm};
use crate::error::{Error, Result};
use seal_crypto::prelude::KeyBasedDerivation;
use seal_crypto::schemes::kdf::hkdf::{HkdfSha256, HkdfSha384, HkdfSha512};
use seal_crypto::zeroize::Zeroizing;
use crate::traits::KdfKeyAlgorithmTrait;

#[derive(Clone, Default)]
pub struct HkdfSha256Wrapper {
    algorithm: HkdfSha256,
}

impl KdfKeyAlgorithmTrait for HkdfSha256Wrapper {
    fn derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.algorithm
            .derive(
                ikm,
                salt,
                info,
                output_len,
            )
            .map(|dk| dk.0)
            .map_err(Error::from)
    }

    fn algorithm(&self) -> KdfKeyAlgorithm {
        KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha256)
    }

    fn clone_box(&self) -> Box<dyn KdfKeyAlgorithmTrait> {
        Box::new(self.clone())
    }
}

#[derive(Clone, Default)]
pub struct HkdfSha384Wrapper {
    algorithm: HkdfSha384,
}

impl KdfKeyAlgorithmTrait for HkdfSha384Wrapper {
    fn derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.algorithm
            .derive(
                ikm,
                salt,
                info,
                output_len,
            )
            .map(|dk| dk.0)
            .map_err(Error::from)
    }

    fn algorithm(&self) -> KdfKeyAlgorithm {
        KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha384)
    }

    fn clone_box(&self) -> Box<dyn KdfKeyAlgorithmTrait> {
        Box::new(self.clone())
    }
}

#[derive(Clone, Default)]
pub struct HkdfSha512Wrapper {
    algorithm: HkdfSha512,
}

impl KdfKeyAlgorithmTrait for HkdfSha512Wrapper {
    fn derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.algorithm
            .derive(ikm, salt, info, output_len)
            .map(|dk| dk.0)
            .map_err(Error::from)
    }

    fn algorithm(&self) -> KdfKeyAlgorithm {
        KdfKeyAlgorithm::Hkdf(HashAlgorithmEnum::Sha512)
    }

    fn clone_box(&self) -> Box<dyn KdfKeyAlgorithmTrait> {
        Box::new(self.clone())
    }
}

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
        Box::new(self.clone())
    }
}

impl KdfKeyWrapper {
    pub fn new(algorithm: Box<dyn KdfKeyAlgorithmTrait>) -> Self {
        Self { algorithm }
    }
}
