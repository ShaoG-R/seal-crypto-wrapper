use crate::algorithms::asymmetric::signature::{DilithiumSecurityLevel, SignatureAlgorithm};
use crate::error::{Error, FormatError, Result};
use crate::keys::asymmetric::signature::{
    TypedSignatureKeyPair, TypedSignaturePrivateKey, TypedSignaturePublicKey,
};
use crate::traits::SignatureAlgorithmTrait;
use seal_crypto::prelude::{AsymmetricKeySet, Key, Signature, Signer, Verifier};
use seal_crypto::schemes::asymmetric::post_quantum::dilithium::{
    Dilithium2, Dilithium3, Dilithium5,
};
use seal_crypto::schemes::asymmetric::traditional::ecc::{EcdsaP256, Ed25519};
use std::ops::Deref;
use crate::define_wrapper;
use crate::keys::asymmetric::{TypedAsymmetricPrivateKeyTrait, TypedAsymmetricPublicKeyTrait};

macro_rules! impl_signature_algorithm {
    ($wrapper:ident, $algo:ty, $algo_enum:expr) => {
        define_wrapper!(@unit_struct, $wrapper, SignatureAlgorithmTrait, {
            fn algorithm(&self) -> SignatureAlgorithm {
                $algo_enum
            }

            fn sign(&self, message: &[u8], key: &TypedSignaturePrivateKey) -> Result<Vec<u8>> {
                if key.algorithm != $algo_enum {
                    return Err(Error::FormatError(FormatError::InvalidKeyType));
                }
                type KT = $algo;
                let sk = <KT as AsymmetricKeySet>::PrivateKey::from_bytes(&key.to_bytes())?;
                let sig = KT::sign(&sk, message)?;
                Ok(sig.0)
            }

            fn verify(
                &self,
                message: &[u8],
                key: &TypedSignaturePublicKey,
                signature: Vec<u8>,
            ) -> Result<()> {
                if key.algorithm != $algo_enum {
                    return Err(Error::FormatError(FormatError::InvalidKeyType));
                }
                type KT = $algo;
                let pk = <KT as AsymmetricKeySet>::PublicKey::from_bytes(&key.to_bytes())?;
                KT::verify(&pk, message, &Signature(signature))?;
                Ok(())
            }

            fn generate_keypair(&self) -> Result<TypedSignatureKeyPair> {
                TypedSignatureKeyPair::generate($algo_enum)
            }

            fn clone_box(&self) -> Box<dyn SignatureAlgorithmTrait> {
                Box::new(self.clone())
            }
        });
    };
}

#[derive(Clone)]
pub struct SignatureAlgorithmWrapper {
    algorithm: Box<dyn SignatureAlgorithmTrait>,
}

impl Deref for SignatureAlgorithmWrapper {
    type Target = Box<dyn SignatureAlgorithmTrait>;

    fn deref(&self) -> &Self::Target {
        &self.algorithm
    }
}

impl SignatureAlgorithmWrapper {
    pub fn new(algorithm: Box<dyn SignatureAlgorithmTrait>) -> Self {
        Self { algorithm }
    }

    pub fn from_enum(algorithm: SignatureAlgorithm) -> Self {
        let algorithm: Box<dyn SignatureAlgorithmTrait> = match algorithm {
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L2) => {
                Box::new(Dilithium2Wrapper::new())
            }
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L3) => {
                Box::new(Dilithium3Wrapper::new())
            }
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L5) => {
                Box::new(Dilithium5Wrapper::new())
            }
            SignatureAlgorithm::Ed25519 => Box::new(Ed25519Wrapper::new()),
            SignatureAlgorithm::EcdsaP256 => Box::new(EcdsaP256Wrapper::new()),
        };
        Self::new(algorithm)
    }
}

impl SignatureAlgorithmTrait for SignatureAlgorithmWrapper {
    fn sign(&self, message: &[u8], key: &TypedSignaturePrivateKey) -> Result<Vec<u8>> {
        self.algorithm.sign(message, key)
    }

    fn verify(
        &self,
        message: &[u8],
        key: &TypedSignaturePublicKey,
        signature: Vec<u8>,
    ) -> Result<()> {
        self.algorithm.verify(message, key, signature)
    }

    fn generate_keypair(&self) -> Result<TypedSignatureKeyPair> {
        self.algorithm.generate_keypair()
    }

    fn clone_box(&self) -> Box<dyn SignatureAlgorithmTrait> {
        self.algorithm.clone_box()
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm.algorithm()
    }
}

impl From<SignatureAlgorithm> for SignatureAlgorithmWrapper {
    fn from(value: SignatureAlgorithm) -> Self {
        Self::from_enum(value)
    }
}

impl From<Box<dyn SignatureAlgorithmTrait>> for SignatureAlgorithmWrapper {
    fn from(value: Box<dyn SignatureAlgorithmTrait>) -> Self {
        Self::new(value)
    }
}

impl_signature_algorithm!(
    Dilithium2Wrapper,
    Dilithium2,
    SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L2)
);
impl_signature_algorithm!(
    Dilithium3Wrapper,
    Dilithium3,
    SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L3)
);
impl_signature_algorithm!(
    Dilithium5Wrapper,
    Dilithium5,
    SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L5)
);
impl_signature_algorithm!(Ed25519Wrapper, Ed25519, SignatureAlgorithm::Ed25519);
impl_signature_algorithm!(EcdsaP256Wrapper, EcdsaP256, SignatureAlgorithm::EcdsaP256);
