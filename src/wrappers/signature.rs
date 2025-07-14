use crate::algorithms::SignatureAlgorithmEnum;
use crate::error::{Error, FormatError, Result};
use crate::keys::signature::{
    TypedSignatureKeyPair, TypedSignaturePrivateKey, TypedSignaturePublicKey,
};
use crate::traits::SignatureAlgorithmTrait;
use seal_crypto::prelude::{AsymmetricKeySet, Key, Signature, Signer, Verifier};
use seal_crypto::schemes::asymmetric::post_quantum::dilithium::{
    Dilithium2, Dilithium3, Dilithium5,
};
use seal_crypto::schemes::asymmetric::traditional::ecc::{EcdsaP256, Ed25519};
use std::ops::Deref;

macro_rules! impl_signature_algorithm {
    ($wrapper:ident, $algo:ty, $algo_enum:path) => {
        #[derive(Clone, Debug, Default)]
        pub struct $wrapper;

        impl $wrapper {
            pub fn new() -> Self {
                Self
            }
        }

        impl From<$wrapper> for Box<dyn SignatureAlgorithmTrait> {
            fn from(wrapper: $wrapper) -> Self {
                Box::new(wrapper)
            }
        }

        impl SignatureAlgorithmTrait for $wrapper {
            fn algorithm(&self) -> SignatureAlgorithmEnum {
                $algo_enum
            }

            fn sign(&self, message: &[u8], key: &TypedSignaturePrivateKey) -> Result<Vec<u8>> {
                if key.algorithm() != $algo_enum {
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
                if key.algorithm() != $algo_enum {
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
        }
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

    pub fn from_enum(algorithm: SignatureAlgorithmEnum) -> Self {
        let algorithm: Box<dyn SignatureAlgorithmTrait> = match algorithm {
            SignatureAlgorithmEnum::Dilithium2 => Box::new(Dilithium2Wrapper::new()),
            SignatureAlgorithmEnum::Dilithium3 => Box::new(Dilithium3Wrapper::new()),
            SignatureAlgorithmEnum::Dilithium5 => Box::new(Dilithium5Wrapper::new()),
            SignatureAlgorithmEnum::Ed25519 => Box::new(Ed25519Wrapper::new()),
            SignatureAlgorithmEnum::EcdsaP256 => Box::new(EcdsaP256Wrapper::new()),
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

    fn algorithm(&self) -> SignatureAlgorithmEnum {
        self.algorithm.algorithm()
    }
}

impl From<SignatureAlgorithmEnum> for SignatureAlgorithmWrapper {
    fn from(value: SignatureAlgorithmEnum) -> Self {
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
    SignatureAlgorithmEnum::Dilithium2
);
impl_signature_algorithm!(
    Dilithium3Wrapper,
    Dilithium3,
    SignatureAlgorithmEnum::Dilithium3
);
impl_signature_algorithm!(
    Dilithium5Wrapper,
    Dilithium5,
    SignatureAlgorithmEnum::Dilithium5
);
impl_signature_algorithm!(Ed25519Wrapper, Ed25519, SignatureAlgorithmEnum::Ed25519);
impl_signature_algorithm!(
    EcdsaP256Wrapper,
    EcdsaP256,
    SignatureAlgorithmEnum::EcdsaP256
);
