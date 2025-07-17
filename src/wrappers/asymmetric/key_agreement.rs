use crate::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;
use crate::error::{Error, Result};
use crate::keys::asymmetric::key_agreement::{
    TypedKeyAgreementKeyPair, TypedKeyAgreementPrivateKey, TypedKeyAgreementPublicKey,
};
use crate::traits::KeyAgreementAlgorithmTrait;
use seal_crypto::prelude::{AsymmetricKeySet, Key, KeyAgreement};
use seal_crypto::schemes::asymmetric::traditional::ecdh::EcdhP256;
use seal_crypto::zeroize::Zeroizing;
use std::ops::Deref;
use crate::define_wrapper;

macro_rules! impl_key_agreement_algorithm {
    ($wrapper:ident, $algo:ty, $algo_enum:expr) => {
        define_wrapper!(@unit_struct, $wrapper, KeyAgreementAlgorithmTrait, {
            fn algorithm(&self) -> KeyAgreementAlgorithm {
                $algo_enum
            }

            fn agree(
                &self,
                sk: &TypedKeyAgreementPrivateKey,
                pk: &TypedKeyAgreementPublicKey,
            ) -> Result<Zeroizing<Vec<u8>>> {
                if sk.algorithm() != $algo_enum || pk.algorithm() != $algo_enum {
                    return Err(Error::FormatError(
                        crate::error::FormatError::InvalidKeyType,
                    ));
                }
                type KT = $algo;
                let private_key =
                    <KT as AsymmetricKeySet>::PrivateKey::from_bytes(&sk.to_bytes())?;
                let public_key =
                    <KT as AsymmetricKeySet>::PublicKey::from_bytes(&pk.to_bytes())?;
                let shared_secret = KT::agree(&private_key, &public_key)?;
                Ok(shared_secret)
            }

            fn generate_keypair(&self) -> Result<TypedKeyAgreementKeyPair> {
                TypedKeyAgreementKeyPair::generate($algo_enum)
            }

            fn clone_box(&self) -> Box<dyn KeyAgreementAlgorithmTrait> {
                Box::new(self.clone())
            }
        });
    };
}

#[derive(Clone)]
pub struct KeyAgreementAlgorithmWrapper {
    algorithm: Box<dyn KeyAgreementAlgorithmTrait>,
}

impl Deref for KeyAgreementAlgorithmWrapper {
    type Target = Box<dyn KeyAgreementAlgorithmTrait>;

    fn deref(&self) -> &Self::Target {
        &self.algorithm
    }
}

impl KeyAgreementAlgorithmWrapper {
    pub fn new(algorithm: Box<dyn KeyAgreementAlgorithmTrait>) -> Self {
        Self { algorithm }
    }

    pub fn from_enum(algorithm: KeyAgreementAlgorithm) -> Self {
        let algorithm: Box<dyn KeyAgreementAlgorithmTrait> = match algorithm {
            KeyAgreementAlgorithm::EcdhP256 => Box::new(EcdhP256Wrapper::new()),
        };
        Self::new(algorithm)
    }
}

impl KeyAgreementAlgorithmTrait for KeyAgreementAlgorithmWrapper {
    fn agree(
        &self,
        sk: &TypedKeyAgreementPrivateKey,
        pk: &TypedKeyAgreementPublicKey,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.algorithm.agree(sk, pk)
    }

    fn generate_keypair(&self) -> Result<TypedKeyAgreementKeyPair> {
        self.algorithm.generate_keypair()
    }

    fn clone_box(&self) -> Box<dyn KeyAgreementAlgorithmTrait> {
        self.algorithm.clone_box()
    }

    fn algorithm(&self) -> KeyAgreementAlgorithm {
        self.algorithm.algorithm()
    }
}

impl From<KeyAgreementAlgorithm> for KeyAgreementAlgorithmWrapper {
    fn from(value: KeyAgreementAlgorithm) -> Self {
        Self::from_enum(value)
    }
}

impl From<Box<dyn KeyAgreementAlgorithmTrait>> for KeyAgreementAlgorithmWrapper {
    fn from(value: Box<dyn KeyAgreementAlgorithmTrait>) -> Self {
        Self::new(value)
    }
}

impl_key_agreement_algorithm!(EcdhP256Wrapper, EcdhP256, KeyAgreementAlgorithm::EcdhP256);
