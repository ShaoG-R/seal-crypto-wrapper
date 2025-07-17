use crate::algorithms::HashAlgorithmEnum;
use crate::algorithms::kdf::passwd::KdfPasswordAlgorithm;
use crate::error::{Error, Result};
use crate::traits::KdfPasswordAlgorithmTrait;
use seal_crypto::prelude::PasswordBasedDerivation;
use seal_crypto::schemes::kdf::{
    argon2::Argon2,
    pbkdf2::{Pbkdf2Sha256, Pbkdf2Sha384, Pbkdf2Sha512},
};
use seal_crypto::secrecy::SecretBox;
use seal_crypto::zeroize::Zeroizing;
use crate::define_wrapper;
use std::ops::Deref;

macro_rules! impl_kdf_argon2_algorithm {
    ($wrapper:ident, $algo:ty, $algo_enum:path) => {
        define_wrapper!(
            @struct_with_algorithm,
            $wrapper,
            $algo,
            KdfPasswordAlgorithmTrait,
            {
                fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
                    Self {
                        algorithm: <$algo>::new(m_cost, t_cost, p_cost),
                    }
                }
            },
            {
                fn derive(
                    &self,
                    password: &SecretBox<[u8]>,
                    salt: &[u8],
                    output_len: usize,
                ) -> Result<Zeroizing<Vec<u8>>> {
                    self.algorithm
                        .derive(password, salt, output_len)
                        .map(|dk| dk.0)
                        .map_err(Error::from)
                }

                fn algorithm(&self) -> KdfPasswordAlgorithm {
                    $algo_enum {
                        m_cost: self.algorithm.m_cost,
                        t_cost: self.algorithm.t_cost,
                        p_cost: self.algorithm.p_cost,
                    }
                }

                fn clone_box(&self) -> Box<dyn KdfPasswordAlgorithmTrait> {
                    Box::new(self.clone())
                }
            }
        );
    };
}

macro_rules! impl_kdf_pbkdf_algorithm {
    ($wrapper:ident, $algo:ty, $hash_enum:expr) => {
        define_wrapper!(
            @struct_with_algorithm,
            $wrapper,
            $algo,
            KdfPasswordAlgorithmTrait,
            {
                fn new(#[allow(unused_variables)] c: u32) -> Self {
                    Self {
                        algorithm: <$algo>::new(c),
                    }
                }
            },
            {
                fn derive(
                    &self,
                    password: &SecretBox<[u8]>,
                    salt: &[u8],
                    output_len: usize,
                ) -> Result<Zeroizing<Vec<u8>>> {
                    self.algorithm
                        .derive(password, salt, output_len)
                        .map(|dk| dk.0)
                        .map_err(Error::from)
                }

                fn algorithm(&self) -> KdfPasswordAlgorithm {
                    unimplemented!()
                }

                fn clone_box(&self) -> Box<dyn KdfPasswordAlgorithmTrait> {
                    Box::new(self.clone())
                }
            }
        );
    };
}

impl_kdf_argon2_algorithm!(Argon2Wrapper, Argon2, KdfPasswordAlgorithm::Argon2);

impl_kdf_pbkdf_algorithm!(
    Pbkdf2Sha256Wrapper,
    Pbkdf2Sha256,
    HashAlgorithmEnum::Sha256
);
impl_kdf_pbkdf_algorithm!(
    Pbkdf2Sha384Wrapper,
    Pbkdf2Sha384,
    HashAlgorithmEnum::Sha384
);
impl_kdf_pbkdf_algorithm!(
    Pbkdf2Sha512Wrapper,
    Pbkdf2Sha512,
    HashAlgorithmEnum::Sha512
);

#[derive(Clone)]
pub struct KdfPasswordWrapper {
    algorithm: Box<dyn KdfPasswordAlgorithmTrait>,
}

impl KdfPasswordWrapper {
    pub fn new(algorithm: Box<dyn KdfPasswordAlgorithmTrait>) -> Self {
        Self { algorithm }
    }
}

impl Deref for KdfPasswordWrapper {
    type Target = Box<dyn KdfPasswordAlgorithmTrait>;

    fn deref(&self) -> &Self::Target {
        &self.algorithm
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
        self.algorithm.clone_box()
    }
}

impl From<KdfPasswordAlgorithm> for KdfPasswordWrapper {
    fn from(algorithm: KdfPasswordAlgorithm) -> Self {
        algorithm.into_kdf_password_wrapper()
    }
}

impl From<Box<dyn KdfPasswordAlgorithmTrait>> for KdfPasswordWrapper {
    fn from(algorithm: Box<dyn KdfPasswordAlgorithmTrait>) -> Self {
        Self::new(algorithm)
    }
}
