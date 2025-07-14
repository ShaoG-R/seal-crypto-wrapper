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
                let key =
                    <KT as seal_crypto::prelude::SymmetricKeySet>::Key::from_bytes(key.as_bytes())?;
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
                let key =
                    <KT as seal_crypto::prelude::SymmetricKeySet>::Key::from_bytes(key.as_bytes())?;
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
                let key =
                    <KT as seal_crypto::prelude::SymmetricKeySet>::Key::from_bytes(key.as_bytes())?;
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
                let key =
                    <KT as seal_crypto::prelude::SymmetricKeySet>::Key::from_bytes(key.as_bytes())?;
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

#[cfg(test)]
mod tests {
    use crate::algorithms::kdf::key::KdfKeyAlgorithm;
    use crate::keys::symmetric::SymmetricKey;
    use crate::wrappers::kdf::passwd::{KdfPasswordWrapper, Pbkdf2Sha256Wrapper};
    use seal_crypto::secrecy::SecretBox;

    #[test]
    fn test_symmetric_key_generate() {
        use crate::keys::symmetric::SymmetricKey;
        use seal_crypto::{prelude::SymmetricCipher, schemes::symmetric::aes_gcm::Aes256Gcm};

        let key_len = <Aes256Gcm as SymmetricCipher>::KEY_SIZE;
        let key1 = SymmetricKey::generate(key_len).unwrap();
        let key2 = SymmetricKey::generate(key_len).unwrap();

        assert_eq!(key1.as_bytes().len(), key_len);
        assert_eq!(key2.as_bytes().len(), key_len);
        assert_ne!(
            key1.as_bytes(),
            key2.as_bytes(),
            "Generated keys should be unique"
        );
    }

    #[test]
    fn test_symmetric_key_from_bytes() {
        let key_bytes = vec![0u8; 32];
        let key = SymmetricKey::new(key_bytes.clone());

        assert_eq!(key.as_bytes(), key_bytes.as_slice());
    }

    #[test]
    fn test_symmetric_key_derive_key() {
        // 使用HKDF-SHA256进行密钥派生
        let master_key = SymmetricKey::new(vec![0u8; 32]);

        // 使用不同的上下文信息派生出不同的子密钥
        let salt = b"salt_value";
        let info1 = b"encryption_key";
        let info2 = b"signing_key";

        let derived_key1 = master_key
            .derive_key(
                KdfKeyAlgorithm::build().hkdf_sha256(),
                Some(salt),
                Some(info1),
                32,
            )
            .unwrap();
        let derived_key2 = master_key
            .derive_key(
                KdfKeyAlgorithm::build().hkdf_sha256(),
                Some(salt),
                Some(info2),
                32,
            )
            .unwrap();

        // 相同的主密钥和参数应该产生相同的派生密钥
        let derived_key1_again = master_key
            .derive_key(
                KdfKeyAlgorithm::build().hkdf_sha256(),
                Some(salt),
                Some(info1),
                32,
            )
            .unwrap();

        // 不同的上下文信息应该产生不同的派生密钥
        assert_ne!(derived_key1.as_bytes(), derived_key2.as_bytes());

        // 相同的参数应该产生相同的派生密钥
        assert_eq!(derived_key1.as_bytes(), derived_key1_again.as_bytes());
    }

    #[test]
    fn test_symmetric_key_derive_from_password() {
        // 使用PBKDF2-SHA256从密码派生密钥
        let password = SecretBox::new(Box::from(b"my_secure_password".as_slice()));
        let salt = b"random_salt_value";

        // 设置较少的迭代次数以加速测试（实际应用中应使用更多迭代）
        let deriver = KdfPasswordWrapper::new(Box::new(Pbkdf2Sha256Wrapper::new(1000)));

        let derived_key1 =
            SymmetricKey::derive_from_password(&password, deriver.clone(), salt, 32).unwrap();

        // 相同的密码、盐和迭代次数应该产生相同的密钥
        let derived_key2 =
            SymmetricKey::derive_from_password(&password, deriver.clone(), salt, 32).unwrap();

        assert_eq!(derived_key1.as_bytes(), derived_key2.as_bytes());

        // 不同的密码应该产生不同的密钥
        let different_password = SecretBox::new(Box::from(b"different_password".as_slice()));
        let derived_key3 =
            SymmetricKey::derive_from_password(&different_password, deriver.clone(), salt, 32)
                .unwrap();

        assert_ne!(derived_key1.as_bytes(), derived_key3.as_bytes());

        // 不同的盐应该产生不同的密钥
        let different_salt = b"different_salt_value";
        let derived_key4 =
            SymmetricKey::derive_from_password(&password, deriver.clone(), different_salt, 32)
                .unwrap();

        assert_ne!(derived_key1.as_bytes(), derived_key4.as_bytes());
    }

    #[test]
    fn test_key_derivation_output_length() {
        let master_key = SymmetricKey::new(vec![0u8; 32]);
        let deriver = KdfKeyAlgorithm::build().hkdf_sha256();
        let salt = b"salt";
        let info = b"info";

        // 测试不同长度的输出
        let key_16 = master_key
            .derive_key(deriver.clone(), Some(salt), Some(info), 16)
            .unwrap();
        let key_32 = master_key
            .derive_key(deriver.clone(), Some(salt), Some(info), 32)
            .unwrap();
        let key_64 = master_key
            .derive_key(deriver.clone(), Some(salt), Some(info), 64)
            .unwrap();

        assert_eq!(key_16.as_bytes().len(), 16);
        assert_eq!(key_32.as_bytes().len(), 32);
        assert_eq!(key_64.as_bytes().len(), 64);
    }
}
