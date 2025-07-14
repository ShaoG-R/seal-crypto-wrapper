//! This module defines byte wrappers for cryptographic keys.
//!
//! 这个模块为加密密钥定义了字节包装器。
pub mod asymmetric;
pub mod signature;
pub mod symmetric;



#[cfg(test)]
mod tests {
    use crate::algorithms::kdf::key::KdfKeyAlgorithm;
    use crate::keys::symmetric::SymmetricKey;
    use crate::wrappers::kdf::passwd::{KdfPasswordWrapper, Pbkdf2Sha256Wrapper};
    use seal_crypto::secrecy::SecretBox;

    #[test]
    fn test_symmetric_key_generate() {
        use seal_crypto::{prelude::SymmetricCipher, schemes::symmetric::aes_gcm::Aes256Gcm};
        use crate::keys::symmetric::SymmetricKey;

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
            .derive_key(KdfKeyAlgorithm::build().hkdf_sha256(), Some(salt), Some(info1), 32)
            .unwrap();
        let derived_key2 = master_key
            .derive_key(KdfKeyAlgorithm::build().hkdf_sha256(), Some(salt), Some(info2), 32)
            .unwrap();

        // 相同的主密钥和参数应该产生相同的派生密钥
        let derived_key1_again = master_key
            .derive_key(KdfKeyAlgorithm::build().hkdf_sha256(), Some(salt), Some(info1), 32)
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
            SymmetricKey::derive_from_password(&different_password, deriver.clone(), salt, 32).unwrap();

        assert_ne!(derived_key1.as_bytes(), derived_key3.as_bytes());

        // 不同的盐应该产生不同的密钥
        let different_salt = b"different_salt_value";
        let derived_key4 =
            SymmetricKey::derive_from_password(&password, deriver.clone(), different_salt, 32).unwrap();

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
