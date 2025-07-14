use crate::algorithms::symmetric::{AesKeySize, SymmetricAlgorithm};
use crate::error::{Error, FormatError, Result};
use crate::keys::symmetric::{SymmetricKey as UntypedSymmetricKey, TypedSymmetricKey};
use crate::traits::SymmetricAlgorithmTrait;
use seal_crypto::prelude::{Key, SymmetricCipher, SymmetricDecryptor, SymmetricEncryptor};
use seal_crypto::schemes::symmetric::aes_gcm::{Aes128Gcm, Aes256Gcm};
use seal_crypto::schemes::symmetric::chacha20_poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use std::ops::Deref;

macro_rules! impl_symmetric_algorithm {
    ($wrapper:ident, $algo:ty, $algo_enum:expr) => {
        #[derive(Clone, Debug, Default)]
        pub struct $wrapper;

        impl $wrapper {
            pub fn new() -> Self {
                Self
            }
        }

        impl From<$wrapper> for Box<dyn SymmetricAlgorithmTrait> {
            fn from(wrapper: $wrapper) -> Self {
                Box::new(wrapper)
            }
        }

        impl SymmetricAlgorithmTrait for $wrapper {
            fn encrypt(
                &self,
                key: &TypedSymmetricKey,
                nonce: &[u8],
                plaintext: &[u8],
                aad: Option<&[u8]>,
            ) -> Result<Vec<u8>> {
                if key.algorithm() != $algo_enum {
                    return Err(Error::FormatError(FormatError::InvalidKeyType));
                }
                type KT = $algo;
                let key = <KT as seal_crypto::prelude::SymmetricKeySet>::Key::from_bytes(key.as_bytes())?;
                KT::encrypt(&key, nonce, plaintext, aad).map_err(Error::from)
            }

            fn encrypt_to_buffer(
                &self,
                key: &TypedSymmetricKey,
                nonce: &[u8],
                plaintext: &[u8],
                output: &mut [u8],
                aad: Option<&[u8]>,
            ) -> Result<usize> {
                if key.algorithm() != $algo_enum {
                    return Err(Error::FormatError(FormatError::InvalidKeyType));
                }
                type KT = $algo;
                let key = <KT as seal_crypto::prelude::SymmetricKeySet>::Key::from_bytes(key.as_bytes())?;
                KT::encrypt_to_buffer(&key, nonce, plaintext, output, aad).map_err(Error::from)
            }

            fn decrypt(
                &self,
                key: &TypedSymmetricKey,
                nonce: &[u8],
                aad: Option<&[u8]>,
                ciphertext: &[u8],
            ) -> Result<Vec<u8>> {
                if key.algorithm() != $algo_enum {
                    return Err(Error::FormatError(FormatError::InvalidKeyType));
                }
                type KT = $algo;
                let key = <KT as seal_crypto::prelude::SymmetricKeySet>::Key::from_bytes(key.as_bytes())?;
                KT::decrypt(&key, nonce, ciphertext, aad).map_err(Error::from)
            }

            fn decrypt_to_buffer(
                &self,
                key: &TypedSymmetricKey,
                nonce: &[u8],
                ciphertext: &[u8],
                output: &mut [u8],
                aad: Option<&[u8]>,
            ) -> Result<usize> {
                if key.algorithm() != $algo_enum {
                    return Err(Error::FormatError(FormatError::InvalidKeyType));
                }
                type KT = $algo;
                let key = <KT as seal_crypto::prelude::SymmetricKeySet>::Key::from_bytes(key.as_bytes())?;
                KT::decrypt_to_buffer(&key, nonce, ciphertext, output, aad).map_err(Error::from)
            }

            fn clone_box_symmetric(&self) -> Box<dyn SymmetricAlgorithmTrait> {
                Box::new(self.clone())
            }

            fn algorithm(&self) -> SymmetricAlgorithm {
                $algo_enum
            }

            fn key_size(&self) -> usize {
                <$algo>::KEY_SIZE
            }

            fn nonce_size(&self) -> usize {
                <$algo>::NONCE_SIZE
            }

            fn tag_size(&self) -> usize {
                <$algo>::TAG_SIZE
            }

            fn generate_typed_key(&self) -> Result<TypedSymmetricKey> {
                TypedSymmetricKey::generate($algo_enum)
            }

            fn generate_untyped_key(&self) -> Result<UntypedSymmetricKey> {
                self.generate_typed_key().map(|k| k.untyped())
            }

            fn into_symmetric_boxed(self) -> Box<dyn SymmetricAlgorithmTrait> {
                Box::new(self)
            }
        }
    };
}

#[derive(Clone)]
pub struct SymmetricAlgorithmWrapper {
    pub(crate) algorithm: Box<dyn SymmetricAlgorithmTrait>,
}

impl Deref for SymmetricAlgorithmWrapper {
    type Target = Box<dyn SymmetricAlgorithmTrait>;

    fn deref(&self) -> &Self::Target {
        &self.algorithm
    }
}

impl Into<Box<dyn SymmetricAlgorithmTrait>> for SymmetricAlgorithmWrapper {
    fn into(self) -> Box<dyn SymmetricAlgorithmTrait> {
        self.algorithm
    }
}

impl SymmetricAlgorithmWrapper {
    pub fn new(algorithm: Box<dyn SymmetricAlgorithmTrait>) -> Self {
        Self { algorithm }
    }

    pub fn from_enum(algorithm: SymmetricAlgorithm) -> Self {
        let algorithm: Box<dyn SymmetricAlgorithmTrait> = match algorithm {
            SymmetricAlgorithm::AesGcm(AesKeySize::K128) => Box::new(Aes128GcmWrapper::new()),
            SymmetricAlgorithm::AesGcm(AesKeySize::K256) => Box::new(Aes256GcmWrapper::new()),
            SymmetricAlgorithm::ChaCha20Poly1305 => Box::new(ChaCha20Poly1305Wrapper::new()),
            SymmetricAlgorithm::XChaCha20Poly1305 => Box::new(XChaCha20Poly1305Wrapper::new()),
        };
        Self::new(algorithm)
    }

    pub fn generate_typed_key(&self) -> Result<TypedSymmetricKey> {
        self.algorithm.generate_typed_key()
    }

    pub fn generate_untyped_key(&self) -> Result<UntypedSymmetricKey> {
        self.algorithm.generate_untyped_key()
    }
}

impl SymmetricAlgorithmTrait for SymmetricAlgorithmWrapper {
    fn clone_box_symmetric(&self) -> Box<dyn SymmetricAlgorithmTrait> {
        Box::new(self.clone())
    }

    fn encrypt(
        &self,
        key: &TypedSymmetricKey,
        nonce: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.algorithm.encrypt(key, nonce, plaintext, aad)
    }

    fn encrypt_to_buffer(
        &self,
        key: &TypedSymmetricKey,
        nonce: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
        aad: Option<&[u8]>,
    ) -> Result<usize> {
        self.algorithm
            .encrypt_to_buffer(key, nonce, plaintext, output, aad)
    }

    fn decrypt(
        &self,
        key: &TypedSymmetricKey,
        nonce: &[u8],
        aad: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        self.algorithm.decrypt(key, nonce, aad, ciphertext)
    }

    fn decrypt_to_buffer(
        &self,
        key: &TypedSymmetricKey,
        nonce: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
        aad: Option<&[u8]>,
    ) -> Result<usize> {
        self.algorithm
            .decrypt_to_buffer(key, nonce, ciphertext, output, aad)
    }

    fn generate_typed_key(&self) -> Result<TypedSymmetricKey> {
        self.algorithm.generate_typed_key()
    }

    fn generate_untyped_key(&self) -> Result<UntypedSymmetricKey> {
        self.algorithm.generate_untyped_key()
    }

    fn algorithm(&self) -> SymmetricAlgorithm {
        self.algorithm.algorithm()
    }

    fn key_size(&self) -> usize {
        self.algorithm.key_size()
    }

    fn nonce_size(&self) -> usize {
        self.algorithm.nonce_size()
    }

    fn tag_size(&self) -> usize {
        self.algorithm.tag_size()
    }

    fn into_symmetric_boxed(self) -> Box<dyn SymmetricAlgorithmTrait> {
        self.algorithm
    }
}

impl From<SymmetricAlgorithm> for SymmetricAlgorithmWrapper {
    fn from(algorithm: SymmetricAlgorithm) -> Self {
        Self::from_enum(algorithm)
    }
}

impl From<Box<dyn SymmetricAlgorithmTrait>> for SymmetricAlgorithmWrapper {
    fn from(algorithm: Box<dyn SymmetricAlgorithmTrait>) -> Self {
        Self::new(algorithm)
    }
}

impl_symmetric_algorithm!(
    Aes128GcmWrapper,
    Aes128Gcm,
    SymmetricAlgorithm::AesGcm(AesKeySize::K128)
);

impl_symmetric_algorithm!(
    Aes256GcmWrapper,
    Aes256Gcm,
    SymmetricAlgorithm::AesGcm(AesKeySize::K256)
);

impl_symmetric_algorithm!(
    ChaCha20Poly1305Wrapper,
    ChaCha20Poly1305,
    SymmetricAlgorithm::ChaCha20Poly1305
);

impl_symmetric_algorithm!(
    XChaCha20Poly1305Wrapper,
    XChaCha20Poly1305,
    SymmetricAlgorithm::XChaCha20Poly1305
);
