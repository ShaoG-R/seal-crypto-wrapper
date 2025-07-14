use crate::algorithms::AsymmetricAlgorithmEnum;
use crate::error::{Error, FormatError, Result};
use crate::keys::asymmetric::{
    TypedAsymmetricKeyPair, TypedAsymmetricPrivateKey, TypedAsymmetricPublicKey,
};
use crate::traits::AsymmetricAlgorithmTrait;
use seal_crypto::prelude::{AsymmetricKeySet, Kem, Key};
use seal_crypto::schemes::asymmetric::post_quantum::kyber::{Kyber1024, Kyber512, Kyber768};
use seal_crypto::schemes::asymmetric::traditional::rsa::{Rsa2048, Rsa4096};
use seal_crypto::schemes::hash::Sha256;
use seal_crypto::zeroize::Zeroizing;
use std::ops::Deref;

macro_rules! impl_asymmetric_algorithm {
    ($wrapper:ident, $algo:ty, $algo_enum:path) => {
        #[derive(Clone, Debug, Default)]
        pub struct $wrapper;

        impl $wrapper {
            pub fn new() -> Self {
                Self
            }
        }

        impl From<$wrapper> for Box<dyn AsymmetricAlgorithmTrait> {
            fn from(wrapper: $wrapper) -> Self {
                Box::new(wrapper)
            }
        }

        impl AsymmetricAlgorithmTrait for $wrapper {
            fn algorithm(&self) -> AsymmetricAlgorithmEnum {
                $algo_enum
            }

            fn encapsulate_key(
                &self,
                public_key: &TypedAsymmetricPublicKey,
            ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
                if public_key.algorithm() != $algo_enum {
                    return Err(Error::FormatError(FormatError::InvalidKeyType));
                }
                type KT = $algo;
                let pk = <KT as AsymmetricKeySet>::PublicKey::from_bytes(&public_key.to_bytes())?;
                KT::encapsulate(&pk).map_err(Error::from)
            }

            fn decapsulate_key(
                &self,
                private_key: &TypedAsymmetricPrivateKey,
                encapsulated_key: &Zeroizing<Vec<u8>>,
            ) -> Result<Zeroizing<Vec<u8>>> {
                if private_key.algorithm() != $algo_enum {
                    return Err(Error::FormatError(FormatError::InvalidKeyType));
                }
                type KT = $algo;
                let sk =
                    <KT as AsymmetricKeySet>::PrivateKey::from_bytes(&private_key.to_bytes())?;
                KT::decapsulate(&sk, encapsulated_key).map_err(Error::from)
            }

            fn generate_keypair(&self) -> Result<TypedAsymmetricKeyPair> {
                TypedAsymmetricKeyPair::generate($algo_enum)
            }

            fn clone_box_asymmetric(&self) -> Box<dyn AsymmetricAlgorithmTrait> {
                Box::new(self.clone())
            }

            fn into_asymmetric_boxed(self) -> Box<dyn AsymmetricAlgorithmTrait> {
                Box::new(self)
            }
        }
    };
}

pub struct AsymmetricAlgorithmWrapper {
    pub(crate) algorithm: Box<dyn AsymmetricAlgorithmTrait>,
}

impl Deref for AsymmetricAlgorithmWrapper {
    type Target = Box<dyn AsymmetricAlgorithmTrait>;

    fn deref(&self) -> &Self::Target {
        &self.algorithm
    }
}

impl Into<Box<dyn AsymmetricAlgorithmTrait>> for AsymmetricAlgorithmWrapper {
    fn into(self) -> Box<dyn AsymmetricAlgorithmTrait> {
        self.algorithm
    }
}

impl AsymmetricAlgorithmWrapper {
    pub fn new(algorithm: Box<dyn AsymmetricAlgorithmTrait>) -> Self {
        Self { algorithm }
    }

    pub fn from_enum(algorithm: AsymmetricAlgorithmEnum) -> Self {
        let algorithm: Box<dyn AsymmetricAlgorithmTrait> = match algorithm {
            AsymmetricAlgorithmEnum::Rsa2048Sha256 => Box::new(Rsa2048Sha256Wrapper::new()),
            AsymmetricAlgorithmEnum::Rsa4096Sha256 => Box::new(Rsa4096Sha256Wrapper::new()),
            AsymmetricAlgorithmEnum::Kyber512 => Box::new(Kyber512Wrapper::new()),
            AsymmetricAlgorithmEnum::Kyber768 => Box::new(Kyber768Wrapper::new()),
            AsymmetricAlgorithmEnum::Kyber1024 => Box::new(Kyber1024Wrapper::new()),
        };
        Self::new(algorithm)
    }

    pub fn generate_keypair(&self) -> Result<TypedAsymmetricKeyPair> {
        self.algorithm.generate_keypair()
    }
}

impl AsymmetricAlgorithmTrait for AsymmetricAlgorithmWrapper {
    fn algorithm(&self) -> AsymmetricAlgorithmEnum {
        self.algorithm.algorithm()
    }

    fn encapsulate_key(
        &self,
        public_key: &TypedAsymmetricPublicKey,
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        self.algorithm.encapsulate_key(public_key)
    }

    fn decapsulate_key(
        &self,
        private_key: &TypedAsymmetricPrivateKey,
        encapsulated_key: &Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.algorithm
            .decapsulate_key(private_key, encapsulated_key)
    }

    fn generate_keypair(&self) -> Result<TypedAsymmetricKeyPair> {
        self.algorithm.generate_keypair()
    }

    fn clone_box_asymmetric(&self) -> Box<dyn AsymmetricAlgorithmTrait> {
        self.algorithm.clone_box_asymmetric()
    }

    fn into_asymmetric_boxed(self) -> Box<dyn AsymmetricAlgorithmTrait> {
        self.algorithm
    }
}

impl From<AsymmetricAlgorithmEnum> for AsymmetricAlgorithmWrapper {
    fn from(algorithm: AsymmetricAlgorithmEnum) -> Self {
        Self::from_enum(algorithm)
    }
}

impl From<Box<dyn AsymmetricAlgorithmTrait>> for AsymmetricAlgorithmWrapper {
    fn from(algorithm: Box<dyn AsymmetricAlgorithmTrait>) -> Self {
        Self::new(algorithm)
    }
}

impl_asymmetric_algorithm!(
    Rsa2048Sha256Wrapper,
    Rsa2048<Sha256>,
    AsymmetricAlgorithmEnum::Rsa2048Sha256
);

impl_asymmetric_algorithm!(
    Rsa4096Sha256Wrapper,
    Rsa4096<Sha256>,
    AsymmetricAlgorithmEnum::Rsa4096Sha256
);

impl_asymmetric_algorithm!(
    Kyber512Wrapper,
    Kyber512,
    AsymmetricAlgorithmEnum::Kyber512
);

impl_asymmetric_algorithm!(
    Kyber768Wrapper,
    Kyber768,
    AsymmetricAlgorithmEnum::Kyber768
);

impl_asymmetric_algorithm!(
    Kyber1024Wrapper,
    Kyber1024,
    AsymmetricAlgorithmEnum::Kyber1024
);
