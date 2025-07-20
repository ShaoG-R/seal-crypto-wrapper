use seal_crypto_wrapper::error::Result;
use seal_crypto_wrapper::prelude::*;

fn main() -> Result<()> {
    // 1. Select a password-based KDF algorithm.
    // 1. 选择一个基于密码的 KDF 算法。
    let algorithm = KdfAlgorithm::build().passwd().pbkdf2_sha256_default();
    println!("Selected password-based KDF algorithm: {:?}", algorithm);

    // 2. Get the algorithm wrapper.
    // 2. 获取算法包装器。
    let kdf = algorithm.into_kdf_password_wrapper();
    println!("Got KDF wrapper.");

    // 3. Define the password and salts.
    // 3. 定义密码和盐。
    let password = SecretBox::new(Box::from(b"my-secret-password".as_slice()));
    let salt1 = b"some salt";
    let salt2 = b"another salt";
    println!("Password: <SECRET>");
    println!("Salt 1: {:?}", String::from_utf8_lossy(salt1));
    println!("Salt 2: {:?}", String::from_utf8_lossy(salt2));

    // 4. Derive the first key using salt1.
    // 4. 使用 salt1 派生第一个密钥。
    let key1 = kdf.derive(&password, salt1, 32)?;
    println!("Derived key 1.");

    // 5. Derive the second key using salt2.
    // 5. 使用 salt2 派生第二个密钥。
    let key2 = kdf.derive(&password, salt2, 32)?;
    println!("Derived key 2.");

    // 6. Verify that the derived keys are different.
    // 6. 验证派生的密钥是不同的。
    assert_ne!(key1, key2);
    println!("Successfully verified that the derived keys are different!");

    println!("Key 1 (32 bytes): {:?}", key1);
    println!("Key 2 (32 bytes): {:?}", key2);

    Ok(())
}
