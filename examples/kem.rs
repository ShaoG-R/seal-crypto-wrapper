use seal_crypto_wrapper::error::Result;
use seal_crypto_wrapper::prelude::*;

fn main() -> Result<()> {
    // 1. Select a KEM algorithm.
    // 1. 选择一个 KEM 算法。
    let algorithm = AsymmetricAlgorithm::build().kem().kyber512();
    println!("Selected KEM algorithm: {:?}", algorithm);

    // 2. Get the algorithm wrapper.
    // 2. 获取算法包装器。
    let kem = algorithm.into_asymmetric_wrapper();
    println!("Got KEM wrapper.");

    // 3. Generate a key pair.
    // 3. 生成密钥对。
    let key_pair = kem.generate_keypair()?;
    let (public_key, private_key) = key_pair.into_keypair();
    println!("Generated key pair.");

    // 4. Encapsulate to get a shared secret and a ciphertext.
    // 4. 封装以获取共享密钥和密文。
    let (shared_secret_1, ciphertext) = kem.encapsulate_key(&public_key)?;
    println!("Encapsulated shared secret.");

    // 5. Decapsulate the ciphertext to get the shared secret.
    // 5. 解封装密文以获取共享密钥。
    let shared_secret_2 = kem.decapsulate_key(&private_key, &ciphertext)?;
    println!("Decapsulated ciphertext.");

    // 6. Verify that the shared secrets match.
    // 6. 验证共享密钥是否匹配。
    assert_eq!(shared_secret_1, shared_secret_2);
    println!("Successfully verified that the shared secrets match!");

    Ok(())
}
