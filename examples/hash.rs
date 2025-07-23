use seal_crypto_wrapper::error::Result;
use seal_crypto_wrapper::prelude::*;

fn main() -> Result<()> {
    // === Hashing Example ===
    println!("--- Running Hashing Example ---");

    // 1. Select a hash algorithm.
    // 1. 选择一个哈希算法。
    let algorithm = HashAlgorithm::build().sha256();
    println!("Selected hash algorithm: {:?}", algorithm);

    // 2. Get the algorithm wrapper.
    // 2. 获取算法包装器。
    let hasher = algorithm.into_wrapper();
    println!("Got hash wrapper.");

    // 3. Define the data to be hashed.
    // 3. 定义要哈希的数据。
    let data_to_hash = b"This is the data to be hashed.";
    println!("Data to hash: {:?}", String::from_utf8_lossy(data_to_hash));

    // 4. Hash the data.
    // 4. 哈希数据。
    let digest = hasher.hash(data_to_hash);
    println!("Hashed data (digest): {:x?}", digest);
    assert_eq!(digest.len(), 32); // SHA-256 output is 32 bytes

    println!("--- Hashing Example Finished ---\n");


    // === HMAC Example ===
    println!("--- Running HMAC Example ---");

    // We can reuse the same hasher or create a new one.
    // For demonstration, let's select another algorithm.
    // 我们可以重用同一个哈希器或创建一个新的。
    // 为了演示，我们选择另一个算法。
    let hmac_algorithm = HashAlgorithm::build().sha512();
    println!("Selected HMAC algorithm: {:?}", hmac_algorithm);
    let hmac_hasher = hmac_algorithm.into_wrapper();

    // 1. Define the key and message for HMAC.
    // 1. 定义 HMAC 的密钥和消息。
    let hmac_key = b"my-super-secret-hmac-key";
    let message = b"This message is to be authenticated.";
    println!("HMAC key: (hidden for security)");
    println!("Message to authenticate: {:?}", String::from_utf8_lossy(message));

    // 2. Compute the HMAC.
    // 2. 计算 HMAC。
    let mac = hmac_hasher.hmac(hmac_key, message)?;
    println!("Computed HMAC tag: {:x?}", mac);
    assert_eq!(mac.len(), 64); // SHA-512 output is 64 bytes

    // 3. (Verification) In a real scenario, the recipient would re-compute the HMAC
    //    with the same key and message and compare it with the received tag.
    // 3. (验证) 在实际场景中，接收方会使用相同的密钥和消息重新计算 HMAC，
    //    并与收到的标签进行比较。
    let verification_mac = hmac_hasher.hmac(hmac_key, message)?;
    assert_eq!(mac, verification_mac);
    println!("Successfully verified HMAC tag.");

    println!("--- HMAC Example Finished ---");

    Ok(())
} 