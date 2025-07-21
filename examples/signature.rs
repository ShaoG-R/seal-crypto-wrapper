use seal_crypto_wrapper::error::Result;
use seal_crypto_wrapper::prelude::*;

fn main() -> Result<()> {
    // 1. Select a signature algorithm.
    // 1. 选择一个签名算法。
    let algorithm = AsymmetricAlgorithm::build().signature().ed25519();
    println!("Selected signature algorithm: {:?}", algorithm);

    // 2. Get the algorithm wrapper.
    // 2. 获取算法包装器。
    let signature_scheme = algorithm.into_signature_wrapper();
    println!("Got signature wrapper.");

    // 3. Generate a key pair.
    // 3. 生成密钥对。
    let key_pair = signature_scheme.generate_keypair()?;
    let (public_key, private_key) = key_pair.into_keypair();
    println!("Generated key pair.");

    // 4. Create a message to sign.
    // 4. 创建要签名的消息。
    let message = b"This is a message to be signed.";
    println!("Message to sign: {:?}", String::from_utf8_lossy(message));

    // 5. Sign the message with the private key.
    // 5. 使用私钥对消息进行签名。
    let signature = signature_scheme.sign(message, &private_key)?;
    println!("Signed message.");

    // 6. Verify the signature with the public key.
    // 6. 使用公钥验证签名。
    signature_scheme.verify(message, &public_key, &signature)?;
    println!("Successfully verified the signature!");

    Ok(())
}
