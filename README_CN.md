# Seal Crypto Wrapper

本库是底层加密库 [seal-crypto](https://github.com/seal-io/seal-crypto) 的一个高级 Rust 包装。它的核心目标是提供一个更安全、更易于使用的 API，通过将算法信息与密钥本身紧密绑定，来减少常见的加密误用。

## 核心设计理念

在直接使用底层加密库时，开发者需要自行管理密钥和使用该密钥的算法，这可能导致误用（例如，将为 AES-128-GCM 生成的密钥用在 AES-256-GCM 算法中）。`seal-crypto-wrapper` 通过以下设计来解决这个问题：

- **类型化密钥**：为每种加密原语（对称加密、签名、KEM 等）提供专属的密钥类型，例如 `TypedSymmetricKey` 和 `TypedSignatureKeyPair`。
- **算法绑定**：每个类型化的密钥都强制性地绑定了创建它时所用的具体算法信息（例如 `SymmetricAlgorithm::Aes128Gcm`）。
- **运行时安全检查**：在执行任何加密操作（如加密、签名）之前，库会自动检查传入密钥所绑定的算法是否与当前操作的算法实例匹配。如果不匹配，操作将返回错误，从而防止密钥的误用。
- **便捷的序列化**：密钥结构体可以直接使用 `serde` 进行序列化和反序列化，方便存储和传输。反序列化后，算法信息会自动恢复，无需额外步骤。
- **统一的构建器 API**：提供流畅的链式调用 API 来选择和构建所需的算法实例。

## 功能列表

本库包装了 `seal-crypto` 的核心功能，包括：

- **对称加密**：
  - AES-GCM (128, 256位)
  - ChaCha20Poly1305
  - XChaCha20Poly1305
- **非对称加密**：
  - **密钥封装机制 (KEM)**: Kyber (512, 768, 1024)
  - **数字签名**: Dilithium (L2, L3, L5), Ed25519, ECDSA P256
  - **密钥协商**: ECDH P256
- **密钥派生函数 (KDF)**：
  - **基于密钥 (Key-based)**: HKDF (SHA-256, SHA-384, SHA-512)
  - **基于密码 (Password-based)**: PBKDF2, Argon2
- **可扩展输出函数 (XOF)**：
  - SHAKE (128, 256)

## 安装

将以下内容添加到您的 `Cargo.toml` 文件中：

```toml
[dependencies]
seal-crypto-wrapper = "0.1.2" # 请使用最新版本
```

## 使用示例

以下是一些常见用法的示例。

### 对称加密

```rust
use seal_crypto_wrapper::prelude::*;
use seal_crypto_wrapper::error::Result;

fn main() -> Result<()> {
    // 1. 选择一个对称加密算法。
    let algorithm = SymmetricAlgorithm::build().aes256_gcm();

    // 2. 获取算法包装器。
    let cipher = algorithm.into_wrapper();

    // 3. 生成一个密钥 (密钥已绑定算法信息)。
    let key = cipher.generate_typed_key()?;

    // 4. 创建一个 Nonce。在生产环境中，这应该是随机且唯一的。
    let nonce = vec![0u8; cipher.nonce_size()];
    let aad = b"Authenticated but not encrypted data.";
    let plaintext = b"This is a secret message.";

    // 5. 加密明文。
    let ciphertext = cipher.encrypt(&key, &nonce, plaintext, Some(aad))?;

    // 6. 解密密文。
    let decrypted_plaintext = cipher.decrypt(&key, &nonce, Some(aad), &ciphertext)?;

    // 7. 验证解密后的明文与原始明文匹配。
    assert_eq!(plaintext.as_ref(), decrypted_plaintext.as_slice());
    println!("Symmetric encryption/decryption successful!");
    
    Ok(())
}
```

### 数字签名

```rust
use seal_crypto_wrapper::prelude::*;
use seal_crypto_wrapper::error::Result;

fn main() -> Result<()> {
    // 1. 选择一个签名算法。
    let algorithm = AsymmetricAlgorithm::build().signature().ed25519();

    // 2. 获取算法包装器。
    let signature_scheme = algorithm.into_wrapper();

    // 3. 生成密钥对。
    let key_pair = signature_scheme.generate_keypair()?;
    let (public_key, private_key) = key_pair.into_keypair();

    // 4. 创建要签名的消息。
    let message = b"This is a message to be signed.";

    // 5. 使用私钥对消息进行签名。
    let signature = signature_scheme.sign(message, &private_key)?;

    // 6. 使用公钥验证签名。
    signature_scheme.verify(message, &public_key, signature)?;
    println!("Signature verification successful!");

    Ok(())
}
```

### 密钥封装 (KEM)

```rust
use seal_crypto_wrapper::prelude::*;
use seal_crypto_wrapper::error::Result;

fn main() -> Result<()> {
    // 1. 选择一个 KEM 算法。
    let algorithm = AsymmetricAlgorithm::build().kem().kyber512();

    // 2. 获取算法包装器。
    let kem = algorithm.into_asymmetric_wrapper();

    // 3. 生成密钥对。
    let key_pair = kem.generate_keypair()?;
    let (public_key, private_key) = key_pair.into_keypair();

    // 4. 封装以获取共享密钥和密文。
    let (shared_secret_1, ciphertext) = kem.encapsulate_key(&public_key)?;

    // 5. 解封装密文以获取共享密钥。
    let shared_secret_2 = kem.decapsulate_key(&private_key, &ciphertext)?;

    // 6. 验证共享密钥是否匹配。
    assert_eq!(shared_secret_1, shared_secret_2);
    println!("KEM successful, shared secrets match!");

    Ok(())
}
```

### 密钥协商

```rust
use seal_crypto_wrapper::prelude::*;
use seal_crypto_wrapper::error::Result;

fn main() -> Result<()> {
    // 1. 选择一个密钥协商算法。
    let algorithm = AsymmetricAlgorithm::build().key_agreement().ecdh_p256();

    // 2. 获取算法包装器。
    let key_agreement = algorithm.into_wrapper();

    // 3. 参与方 1 和 2 分别生成自己的密钥对。
    let key_pair_1 = key_agreement.generate_keypair()?;
    let (public_key_1, private_key_1) = key_pair_1.into_keypair();

    let key_pair_2 = key_agreement.generate_keypair()?;
    let (public_key_2, private_key_2) = key_pair_2.into_keypair();

    // 4. 参与方 1 使用自己的私钥和参与方 2 的公钥协商出共享密钥。
    let shared_secret_1 = key_agreement.agree(&private_key_1, &public_key_2)?;

    // 5. 参与方 2 使用自己的私钥和参与方 1 的公钥协商出共享密钥。
    let shared_secret_2 = key_agreement.agree(&private_key_2, &public_key_1)?;

    // 6. 验证共享密钥是否匹配。
    assert_eq!(shared_secret_1, shared_secret_2);
    println!("Key agreement successful, shared secrets match!");

    Ok(())
}
```

### 可扩展输出函数 (XOF)

```rust
use seal_crypto_wrapper::prelude::*;
use seal_crypto_wrapper::error::Result;

fn main() -> Result<()> {
    // 1. 选择一个 XOF 算法。
    let algorithm = XofAlgorithm::build().shake128();

    // 2. 获取算法包装器。
    let xof = algorithm.into_wrapper();

    // 3. 定义输入密钥材料、盐和信息。
    let ikm = b"input keying material";
    let salt = b"some salt";
    let info = b"some info";

    // 4. 创建一个 XOF 读取器。
    let mut reader = xof.reader(ikm, Some(salt), Some(info))?;

    // 5. 从读取器中读取 32 字节。
    let mut output1 = [0u8; 32];
    reader.read(&mut output1);

    // 6. 从读取器中再读取 64 字节。
    let mut output2 = [0u8; 64];
    reader.read(&mut output2);

    // 7. 验证输出是不同的。
    assert_ne!(&output1[..], &output2[..32]);
    println!("XOF successful, outputs are different as expected!");
    
    Ok(())
}
```

### 基于密钥的密钥派生 (KDF)

```rust
use seal_crypto_wrapper::prelude::*;
use seal_crypto_wrapper::error::Result;

fn main() -> Result<()> {
    // 1. 选择一个基于密钥的 KDF 算法。
    let algorithm = KdfAlgorithm::build().key().hkdf_sha256();

    // 2. 获取算法包装器。
    let kdf = algorithm.into_wrapper();

    // 3. 定义输入密钥材料、盐和不同的信息。
    let ikm = b"input keying material";
    let salt = b"some salt";
    let info1 = b"info for key 1";
    let info2 = b"info for key 2";

    // 4. 使用 info1 派生第一个密钥。
    let key1 = kdf.derive(ikm, Some(salt), Some(info1), 32)?;

    // 5. 使用 info2 派生第二个密钥。
    let key2 = kdf.derive(ikm, Some(salt), Some(info2), 32)?;

    // 6. 验证派生的密钥是不同的。
    assert_ne!(key1, key2);
    println!("Key-based KDF successful, derived keys are different!");

    Ok(())
}
```

### 基于密码的密钥派生 (PBKDF)

```rust
use seal_crypto_wrapper::prelude::*;
use seal_crypto_wrapper::error::Result;

fn main() -> Result<()> {
    // 1. 选择一个基于密码的 KDF 算法。
    let algorithm = KdfAlgorithm::build().passwd().pbkdf2_sha256_default();

    // 2. 获取算法包装器。
    let kdf = algorithm.into_wrapper();

    // 3. 定义密码和不同的盐。
    let password = SecretBox::new(Box::from(b"my-secret-password".as_slice()));
    let salt1 = b"some salt";
    let salt2 = b"another salt";

    // 4. 使用 salt1 派生第一个密钥。
    let key1 = kdf.derive(&password, salt1, 32)?;

    // 5. 使用 salt2 派生第二个密钥。
    let key2 = kdf.derive(&password, salt2, 32)?;

    // 6. 验证派生的密钥是不同的。
    assert_ne!(key1, key2);
    println!("Password-based KDF successful, derived keys are different!");
    
    Ok(())
}
``` 