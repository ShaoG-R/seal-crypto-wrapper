use crate::algorithms::{
    HashAlgorithmEnum,
    asymmetric::{AsymmetricAlgorithm, KyberSecurityLevel, RsaBits},
};
use crate::error::{Error, FormatError, Result};
use crate::keys::asymmetric::{
    TypedAsymmetricKeyPair, TypedAsymmetricPrivateKey, TypedAsymmetricPublicKey,
};
use crate::traits::AsymmetricAlgorithmTrait;
use seal_crypto::prelude::{AsymmetricKeySet, Kem, Key};
use seal_crypto::schemes::asymmetric::post_quantum::kyber::{Kyber512, Kyber768, Kyber1024};
use seal_crypto::schemes::asymmetric::traditional::rsa::{Rsa2048, Rsa4096};
use seal_crypto::schemes::hash::{Sha256, Sha384, Sha512};
use seal_crypto::zeroize::Zeroizing;
use std::ops::Deref;

macro_rules! impl_asymmetric_algorithm {
    ($wrapper:ident, $algo:ty, $algo_enum:expr) => {
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
            fn algorithm(&self) -> AsymmetricAlgorithm {
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
                let sk = <KT as AsymmetricKeySet>::PrivateKey::from_bytes(&private_key.to_bytes())?;
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

    pub fn from_enum(algorithm: AsymmetricAlgorithm) -> Self {
        let algorithm: Box<dyn AsymmetricAlgorithmTrait> = match algorithm {
            AsymmetricAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha256) => {
                Box::new(Rsa2048Sha256Wrapper::new())
            }
            AsymmetricAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha384) => {
                Box::new(Rsa2048Sha384Wrapper::new())
            }
            AsymmetricAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha512) => {
                Box::new(Rsa2048Sha512Wrapper::new())
            }
            AsymmetricAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha256) => {
                Box::new(Rsa4096Sha256Wrapper::new())
            }
            AsymmetricAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha384) => {
                Box::new(Rsa4096Sha384Wrapper::new())
            }
            AsymmetricAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha512) => {
                Box::new(Rsa4096Sha512Wrapper::new())
            }
            AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L512) => {
                Box::new(Kyber512Wrapper::new())
            }
            AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L768) => {
                Box::new(Kyber768Wrapper::new())
            }
            AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L1024) => {
                Box::new(Kyber1024Wrapper::new())
            }
        };
        Self::new(algorithm)
    }

    pub fn generate_keypair(&self) -> Result<TypedAsymmetricKeyPair> {
        self.algorithm.generate_keypair()
    }
}

impl AsymmetricAlgorithmTrait for AsymmetricAlgorithmWrapper {
    fn algorithm(&self) -> AsymmetricAlgorithm {
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

impl From<AsymmetricAlgorithm> for AsymmetricAlgorithmWrapper {
    fn from(algorithm: AsymmetricAlgorithm) -> Self {
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
    AsymmetricAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha256)
);

impl_asymmetric_algorithm!(
    Rsa2048Sha384Wrapper,
    Rsa2048<Sha384>,
    AsymmetricAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha384)
);

impl_asymmetric_algorithm!(
    Rsa2048Sha512Wrapper,
    Rsa2048<Sha512>,
    AsymmetricAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha512)
);

impl_asymmetric_algorithm!(
    Rsa4096Sha256Wrapper,
    Rsa4096<Sha256>,
    AsymmetricAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha256)
);

impl_asymmetric_algorithm!(
    Rsa4096Sha384Wrapper,
    Rsa4096<Sha384>,
    AsymmetricAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha384)
);

impl_asymmetric_algorithm!(
    Rsa4096Sha512Wrapper,
    Rsa4096<Sha512>,
    AsymmetricAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha512)
);

impl_asymmetric_algorithm!(
    Kyber512Wrapper,
    Kyber512,
    AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L512)
);

impl_asymmetric_algorithm!(
    Kyber768Wrapper,
    Kyber768,
    AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L768)
);

impl_asymmetric_algorithm!(
    Kyber1024Wrapper,
    Kyber1024,
    AsymmetricAlgorithm::Kyber(KyberSecurityLevel::L1024)
);
