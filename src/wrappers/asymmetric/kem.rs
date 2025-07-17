use crate::algorithms::{
    asymmetric::kem::{KemAlgorithm, KyberSecurityLevel, RsaBits},
    HashAlgorithmEnum,
};
use crate::error::{Error, FormatError, Result};
use crate::keys::asymmetric::{
    TypedAsymmetricKeyPair, TypedAsymmetricPrivateKey, TypedAsymmetricPublicKey,
};
use crate::traits::KemAlgorithmTrait;
use seal_crypto::prelude::{AsymmetricKeySet, Kem, Key};
use seal_crypto::schemes::asymmetric::post_quantum::kyber::{Kyber1024, Kyber512, Kyber768};
use seal_crypto::schemes::asymmetric::traditional::rsa::{Rsa2048, Rsa4096};
use seal_crypto::schemes::hash::{Sha256, Sha384, Sha512};
use seal_crypto::zeroize::Zeroizing;
use std::ops::Deref;



macro_rules! impl_kem_algorithm {
    ($wrapper:ident, $algo:ty, $algo_enum:expr) => {
        #[derive(Clone, Debug, Default)]
        pub struct $wrapper;

        impl $wrapper {
            pub fn new() -> Self {
                Self
            }
        }

        impl From<$wrapper> for Box<dyn KemAlgorithmTrait> {
            fn from(wrapper: $wrapper) -> Self {
                Box::new(wrapper)
            }
        }

        impl KemAlgorithmTrait for $wrapper {
            fn algorithm(&self) -> KemAlgorithm {
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

            fn clone_box_asymmetric(&self) -> Box<dyn KemAlgorithmTrait> {
                Box::new(self.clone())
            }

            fn into_asymmetric_boxed(self) -> Box<dyn KemAlgorithmTrait> {
                Box::new(self)
            }
        }
    };
}

pub struct KemAlgorithmWrapper {
    pub(crate) algorithm: Box<dyn KemAlgorithmTrait>,
}

impl Deref for KemAlgorithmWrapper {
    type Target = Box<dyn KemAlgorithmTrait>;

    fn deref(&self) -> &Self::Target {
        &self.algorithm
    }
}

impl Into<Box<dyn KemAlgorithmTrait>> for KemAlgorithmWrapper {
    fn into(self) -> Box<dyn KemAlgorithmTrait> {
        self.algorithm
    }
}

impl KemAlgorithmWrapper {
    pub fn new(algorithm: Box<dyn KemAlgorithmTrait>) -> Self {
        Self { algorithm }
    }

    pub fn from_enum(algorithm: KemAlgorithm) -> Self {
        let algorithm: Box<dyn KemAlgorithmTrait> = match algorithm {
            KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha256) => {
                Box::new(Rsa2048Sha256Wrapper::new())
            }
            KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha384) => {
                Box::new(Rsa2048Sha384Wrapper::new())
            }
            KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha512) => {
                Box::new(Rsa2048Sha512Wrapper::new())
            }
            KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha256) => {
                Box::new(Rsa4096Sha256Wrapper::new())
            }
            KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha384) => {
                Box::new(Rsa4096Sha384Wrapper::new())
            }
            KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha512) => {
                Box::new(Rsa4096Sha512Wrapper::new())
            }
            KemAlgorithm::Kyber(KyberSecurityLevel::L512) => {
                Box::new(Kyber512Wrapper::new())
            }
            KemAlgorithm::Kyber(KyberSecurityLevel::L768) => {
                Box::new(Kyber768Wrapper::new())
            }
            KemAlgorithm::Kyber(KyberSecurityLevel::L1024) => {
                Box::new(Kyber1024Wrapper::new())
            }
        };
        Self::new(algorithm)
    }

    pub fn generate_keypair(&self) -> Result<TypedAsymmetricKeyPair> {
        self.algorithm.generate_keypair()
    }
}

impl KemAlgorithmTrait for KemAlgorithmWrapper {
    fn algorithm(&self) -> KemAlgorithm {
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

    fn clone_box_asymmetric(&self) -> Box<dyn KemAlgorithmTrait> {
        self.algorithm.clone_box_asymmetric()
    }

    fn into_asymmetric_boxed(self) -> Box<dyn KemAlgorithmTrait> {
        self.algorithm
    }
}

impl From<KemAlgorithm> for KemAlgorithmWrapper {
    fn from(algorithm: KemAlgorithm) -> Self {
        Self::from_enum(algorithm)
    }
}

impl From<Box<dyn KemAlgorithmTrait>> for KemAlgorithmWrapper {
    fn from(algorithm: Box<dyn KemAlgorithmTrait>) -> Self {
        Self::new(algorithm)
    }
}

impl_kem_algorithm!(
    Rsa2048Sha256Wrapper,
    Rsa2048<Sha256>,
    KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha256)
);

impl_kem_algorithm!(
    Rsa2048Sha384Wrapper,
    Rsa2048<Sha384>,
    KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha384)
);

impl_kem_algorithm!(
    Rsa2048Sha512Wrapper,
    Rsa2048<Sha512>,
    KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithmEnum::Sha512)
);

impl_kem_algorithm!(
    Rsa4096Sha256Wrapper,
    Rsa4096<Sha256>,
    KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha256)
);

impl_kem_algorithm!(
    Rsa4096Sha384Wrapper,
    Rsa4096<Sha384>,
    KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha384)
);

impl_kem_algorithm!(
    Rsa4096Sha512Wrapper,
    Rsa4096<Sha512>,
    KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithmEnum::Sha512)
);

impl_kem_algorithm!(
    Kyber512Wrapper,
    Kyber512,
    KemAlgorithm::Kyber(KyberSecurityLevel::L512)
);

impl_kem_algorithm!(
    Kyber768Wrapper,
    Kyber768,
    KemAlgorithm::Kyber(KyberSecurityLevel::L768)
);

impl_kem_algorithm!(
    Kyber1024Wrapper,
    Kyber1024,
    KemAlgorithm::Kyber(KyberSecurityLevel::L1024)
);
