use seal_crypto_wrapper::prelude::*;
use seal_crypto_wrapper::error::Result;

fn main() -> Result<()> {
    // 1. Select a symmetric algorithm.
    // 1. 选择一个对称加密算法。
    let algorithm = SymmetricAlgorithm::build().aes256_gcm();
    println!("Selected symmetric algorithm: {:?}", algorithm);

    // 2. Get the algorithm wrapper.
    // 2. 获取算法包装器。
    let cipher = algorithm.into_symmetric_wrapper();
    println!("Got symmetric cipher wrapper.");

    // 3. Generate a key.
    // 3. 生成一个密钥。
    let key = cipher.generate_typed_key()?;
    println!("Generated key.");

    // 4. Create a nonce. For production, this should be random and unique.
    // 4. 创建一个 Nonce。在生产环境中，这应该是随机且唯一的。
    let nonce = vec![0u8; cipher.nonce_size()];
    println!("Created nonce.");

    // 5. Define plaintext and additional authenticated data (AAD).
    // 5. 定义明文和附加验证数据 (AAD)。
    let plaintext = b"This is a secret message.";
    let aad = b"Authenticated but not encrypted data.";
    println!("Plaintext: {:?}", String::from_utf8_lossy(plaintext));
    println!("AAD: {:?}", String::from_utf8_lossy(aad));

    // 6. Encrypt the plaintext.
    // 6. 加密明文。
    let ciphertext = cipher.encrypt(&key, &nonce, plaintext, Some(aad))?;
    println!("Encrypted plaintext.");

    // 7. Decrypt the ciphertext.
    // 7. 解密密文。
    let decrypted_plaintext = cipher.decrypt(&key, &nonce, Some(aad), &ciphertext)?;
    println!("Decrypted ciphertext.");

    // 8. Verify the decrypted plaintext matches the original.
    // 8. 验证解密后的明文与原始明文匹配。
    assert_eq!(plaintext.as_ref(), decrypted_plaintext.as_slice());
    println!("Successfully verified that the decrypted plaintext matches the original!");

    Ok(())
} 