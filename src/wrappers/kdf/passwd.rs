use crate::algorithms::kdf::passwd::KdfPasswordAlgorithm;
use crate::algorithms::HashAlgorithmEnum;
use crate::error::{Error, Result};
use seal_crypto::prelude::PasswordBasedDerivation;
use seal_crypto::zeroize::Zeroizing;
use seal_crypto::schemes::kdf::{
    argon2::Argon2,
    pbkdf2::{Pbkdf2Sha256, Pbkdf2Sha384, Pbkdf2Sha512},
};
use seal_crypto::secrecy::SecretBox;
use crate::traits::KdfPasswordAlgorithmTrait;

#[derive(Clone, Default)]
pub struct Argon2Wrapper {
    algorithm: Argon2,
}

impl Argon2Wrapper {
    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
        Self {
            algorithm: Argon2::new(m_cost, t_cost, p_cost),
        }
    }
}

impl KdfPasswordAlgorithmTrait for Argon2Wrapper {
    fn derive(
        &self,
        password: &SecretBox<[u8]>,
        salt: &[u8],
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.algorithm
            .derive(
                password,
                salt,
                output_len,
            )
            .map(|dk| dk.0)
            .map_err(Error::from)
    }

    fn algorithm(&self) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Argon2
    }

    fn clone_box(&self) -> Box<dyn KdfPasswordAlgorithmTrait> {
        Box::new(self.clone())
    }
}

#[derive(Clone, Default)]
pub struct Pbkdf2Sha256Wrapper {
    algorithm: Pbkdf2Sha256,
}

impl Pbkdf2Sha256Wrapper {
    pub fn new(c: u32) -> Self {
        Self {
            algorithm: Pbkdf2Sha256::new(c),
        }
    }
}

impl KdfPasswordAlgorithmTrait for Pbkdf2Sha256Wrapper {
    fn derive(
        &self,
        password: &SecretBox<[u8]>,
        salt: &[u8],
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.algorithm
            .derive(
                password,
                salt,
                output_len,
            )
            .map(|dk| dk.0)
            .map_err(Error::from)
    }

    fn algorithm(&self) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2(HashAlgorithmEnum::Sha256)
    }

    fn clone_box(&self) -> Box<dyn KdfPasswordAlgorithmTrait> {
        Box::new(self.clone())
    }
}

#[derive(Clone, Default)]
pub struct Pbkdf2Sha384Wrapper {
    algorithm: Pbkdf2Sha384,
}

impl Pbkdf2Sha384Wrapper {
    pub fn new(c: u32) -> Self {
        Self {
            algorithm: Pbkdf2Sha384::new(c),
        }
    }
}

impl KdfPasswordAlgorithmTrait for Pbkdf2Sha384Wrapper {
    fn derive(
        &self,
        password: &SecretBox<[u8]>,
        salt: &[u8],
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.algorithm
            .derive(
                password,
                salt,
                output_len,
            )
            .map(|dk| dk.0)
            .map_err(Error::from)
    }

    fn algorithm(&self) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2(HashAlgorithmEnum::Sha384)
    }

    fn clone_box(&self) -> Box<dyn KdfPasswordAlgorithmTrait> {
        Box::new(self.clone())
    }
}

#[derive(Clone, Default)]
pub struct Pbkdf2Sha512Wrapper {
    algorithm: Pbkdf2Sha512,
}

impl Pbkdf2Sha512Wrapper {
    pub fn new(c: u32) -> Self {
        Self {
            algorithm: Pbkdf2Sha512::new(c),
        }
    }
}

impl KdfPasswordAlgorithmTrait for Pbkdf2Sha512Wrapper {
    fn derive(
        &self,
        password: &SecretBox<[u8]>,
        salt: &[u8],
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.algorithm
            .derive(
                password,
                salt,
                output_len,
            )
            .map(|dk| dk.0)
            .map_err(Error::from)
    }

    fn algorithm(&self) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2(HashAlgorithmEnum::Sha512)
    }

    fn clone_box(&self) -> Box<dyn KdfPasswordAlgorithmTrait> {
        Box::new(self.clone())
    }
}

#[derive(Clone)]
pub struct KdfPasswordWrapper {
    algorithm: Box<dyn KdfPasswordAlgorithmTrait>,
}

impl KdfPasswordWrapper {
    pub fn new(algorithm: Box<dyn KdfPasswordAlgorithmTrait>) -> Self {
        Self { algorithm }
    }
}

impl KdfPasswordAlgorithmTrait for KdfPasswordWrapper {
    fn derive(
        &self,
        password: &SecretBox<[u8]>,
        salt: &[u8],
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.algorithm.derive(password, salt, output_len)
    }

    fn algorithm(&self) -> KdfPasswordAlgorithm {
        self.algorithm.algorithm()
    }

    fn clone_box(&self) -> Box<dyn KdfPasswordAlgorithmTrait> {
        Box::new(self.clone())
    }
}
