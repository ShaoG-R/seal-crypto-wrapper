use seal_crypto_wrapper::prelude::*;
use seal_crypto_wrapper::error::Result;

fn main() -> Result<()> {
    // 1. Select a key agreement algorithm.
    // 1. 选择一个密钥协商算法。
    let algorithm = AsymmetricAlgorithm::build().key_agreement().ecdh_p256();
    println!("Selected key agreement algorithm: {:?}", algorithm);

    // 2. Get the algorithm wrapper.
    // 2. 获取算法包装器。
    let key_agreement = algorithm.into_key_agreement_wrapper();
    println!("Got key agreement wrapper.");

    // 3. Generate two key pairs.
    // 3. 生成两个密钥对。
    let key_pair_1 = key_agreement.generate_keypair()?;
    let (public_key_1, private_key_1) = key_pair_1.into_keypair();
    println!("Generated key pair 1.");

    let key_pair_2 = key_agreement.generate_keypair()?;
    let (public_key_2, private_key_2) = key_pair_2.into_keypair();
    println!("Generated key pair 2.");

    // 4. Party 1 agrees on a shared secret.
    // 4. 参与方 1 协商共享密钥。
    let shared_secret_1 = key_agreement.agree(&private_key_1, &public_key_2)?;
    println!("Party 1 agreed on shared secret.");

    // 5. Party 2 agrees on a shared secret.
    // 5. 参与方 2 协商共享密钥。
    let shared_secret_2 = key_agreement.agree(&private_key_2, &public_key_1)?;
    println!("Party 2 agreed on shared secret.");

    // 6. Verify that the shared secrets match.
    // 6. 验证共享密钥是否匹配。
    assert_eq!(shared_secret_1, shared_secret_2);
    println!("Successfully verified that the shared secrets match!");

    Ok(())
} 