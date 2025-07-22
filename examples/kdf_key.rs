use seal_crypto_wrapper::error::Result;
use seal_crypto_wrapper::prelude::*;

fn main() -> Result<()> {
    // 1. Select a key-based KDF algorithm.
    // 1. 选择一个基于密钥的 KDF 算法。
    let algorithm = KdfAlgorithm::build().key().hkdf_sha256();
    println!("Selected KDF algorithm: {:?}", algorithm);

    // 2. Get the algorithm wrapper.
    // 2. 获取算法包装器。
    let kdf = algorithm.into_wrapper();
    println!("Got KDF wrapper.");

    // 3. Define the input keying material, salt, and infos.
    // 3. 定义输入密钥材料、盐和信息。
    let ikm = b"input keying material";
    let salt = b"some salt";
    let info1 = b"info for key 1";
    let info2 = b"info for key 2";
    println!("IKM: {:?}", String::from_utf8_lossy(ikm));
    println!("Salt: {:?}", String::from_utf8_lossy(salt));
    println!("Info 1: {:?}", String::from_utf8_lossy(info1));
    println!("Info 2: {:?}", String::from_utf8_lossy(info2));

    // 4. Derive the first key.
    // 4. 派生第一个密钥。
    let key1 = kdf.derive(ikm, Some(salt), Some(info1), 32)?;
    println!("Derived key 1.");

    // 5. Derive the second key.
    // 5. 派生第二个密钥。
    let key2 = kdf.derive(ikm, Some(salt), Some(info2), 32)?;
    println!("Derived key 2.");

    // 6. Verify that the derived keys are different.
    // 6. 验证派生的密钥是不同的。
    assert_ne!(key1, key2);
    println!("Successfully verified that the derived keys are different!");

    println!("Key 1 (32 bytes): {:?}", key1);
    println!("Key 2 (32 bytes): {:?}", key2);

    Ok(())
}
