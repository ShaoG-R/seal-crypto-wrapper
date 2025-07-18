# Seal Crypto Wrapper

This library is a high-level Rust wrapper for the underlying cryptographic library [seal-crypto](https://github.com/ShaoG-R/seal-crypto). Its core goal is to provide a safer and more user-friendly API by tightly binding algorithm information with the keys themselves, reducing common cryptographic misuse.

A Chinese version of this document is available [here (中文)](README_CN.md).

## Core Design Philosophy

When using a low-level crypto library directly, developers must manage keys and their corresponding algorithms separately. This can lead to misuse, such as using a key generated for AES-128-GCM with an AES-256-GCM cipher. `seal-crypto-wrapper` addresses this issue with the following design:

- **Typed Keys**: Provides dedicated key types for each cryptographic primitive (e.g., symmetric encryption, signatures, KEM), such as `TypedSymmetricKey` and `TypedSignatureKeyPair`.
- **Algorithm Binding**: Every typed key is mandatorily bound to the specific algorithm information used to create it (e.g., `SymmetricAlgorithm::Aes128Gcm`).
- **Runtime Safety Checks**: Before performing any cryptographic operation (like encryption or signing), the library automatically checks if the algorithm bound to the provided key matches the current operation's algorithm instance. If they don't match, the operation returns an error, preventing key misuse.
- **Convenient Serialization**: Key structs can be directly serialized and deserialized using `serde`, simplifying storage and transmission. Upon deserialization, the algorithm information is automatically restored without extra steps.
- **Unified Builder API**: Offers a fluent, chainable API to select and construct the required algorithm instances.

## Feature List

This library wraps the core functionalities of `seal-crypto`, including:

- **Symmetric Ciphers**:
  - AES-GCM (128, 256-bit)
  - ChaCha20Poly1305
  - XChaCha20Poly1305
- **Asymmetric Cryptography**:
  - **Key Encapsulation Mechanism (KEM)**: Kyber (512, 768, 1024)
  - **Digital Signatures**: Dilithium (L2, L3, L5), Ed25519, ECDSA P256
  - **Key Agreement**: ECDH P256
- **Key Derivation Functions (KDF)**:
  - **Key-based**: HKDF (SHA-256, SHA-384, SHA-512)
  - **Password-based**: PBKDF2, Argon2
- **eXtendable-Output Functions (XOF)**:
  - SHAKE (128, 256)

## Installation

Add the following to your `Cargo.toml` file:

```toml
[dependencies]
seal-crypto-wrapper = "0.1.2" # Please use the latest version
```

## Usage Examples

Here are some examples for common use cases.

### Symmetric Encryption

```rust
use seal_crypto_wrapper::prelude::*;
use seal_crypto_wrapper::error::Result;

fn main() -> Result<()> {
    // 1. Select a symmetric algorithm.
    let algorithm = SymmetricAlgorithm::build().aes256_gcm();

    // 2. Get the algorithm wrapper.
    let cipher = algorithm.into_symmetric_wrapper();

    // 3. Generate a key (the key is already bound to the algorithm info).
    let key = cipher.generate_typed_key()?;

    // 4. Create a nonce. For production, this should be random and unique.
    let nonce = vec![0u8; cipher.nonce_size()];
    let aad = b"Authenticated but not encrypted data.";
    let plaintext = b"This is a secret message.";

    // 5. Encrypt the plaintext.
    let ciphertext = cipher.encrypt(&key, &nonce, plaintext, Some(aad))?;

    // 6. Decrypt the ciphertext.
    let decrypted_plaintext = cipher.decrypt(&key, &nonce, Some(aad), &ciphertext)?;

    // 7. Verify the decrypted plaintext matches the original.
    assert_eq!(plaintext.as_ref(), decrypted_plaintext.as_slice());
    println!("Symmetric encryption/decryption successful!");
    
    Ok(())
}
```

### Digital Signatures

```rust
use seal_crypto_wrapper::prelude::*;
use seal_crypto_wrapper::error::Result;

fn main() -> Result<()> {
    // 1. Select a signature algorithm.
    let algorithm = AsymmetricAlgorithm::build().signature().ed25519();

    // 2. Get the algorithm wrapper.
    let signature_scheme = algorithm.into_signature_wrapper();

    // 3. Generate a key pair.
    let key_pair = signature_scheme.generate_keypair()?;
    let (public_key, private_key) = key_pair.into_keypair();

    // 4. Create a message to sign.
    let message = b"This is a message to be signed.";

    // 5. Sign the message with the private key.
    let signature = signature_scheme.sign(message, &private_key)?;

    // 6. Verify the signature with the public key.
    signature_scheme.verify(message, &public_key, signature)?;
    println!("Signature verification successful!");

    Ok(())
}
```

### Key Encapsulation Mechanism (KEM)

```rust
use seal_crypto_wrapper::prelude::*;
use seal_crypto_wrapper::error::Result;

fn main() -> Result<()> {
    // 1. Select a KEM algorithm.
    let algorithm = AsymmetricAlgorithm::build().kem().kyber512();

    // 2. Get the algorithm wrapper.
    let kem = algorithm.into_asymmetric_wrapper();

    // 3. Generate a key pair.
    let key_pair = kem.generate_keypair()?;
    let (public_key, private_key) = key_pair.into_keypair();

    // 4. Encapsulate to get a shared secret and a ciphertext.
    let (shared_secret_1, ciphertext) = kem.encapsulate_key(&public_key)?;

    // 5. Decapsulate the ciphertext to get the shared secret.
    let shared_secret_2 = kem.decapsulate_key(&private_key, &ciphertext)?;

    // 6. Verify that the shared secrets match.
    assert_eq!(shared_secret_1, shared_secret_2);
    println!("KEM successful, shared secrets match!");

    Ok(())
}
```

### Key Agreement

```rust
use seal_crypto_wrapper::prelude::*;
use seal_crypto_wrapper::error::Result;

fn main() -> Result<()> {
    // 1. Select a key agreement algorithm.
    let algorithm = AsymmetricAlgorithm::build().key_agreement().ecdh_p256();

    // 2. Get the algorithm wrapper.
    let key_agreement = algorithm.into_key_agreement_wrapper();

    // 3. Party 1 and Party 2 generate their own key pairs.
    let key_pair_1 = key_agreement.generate_keypair()?;
    let (public_key_1, private_key_1) = key_pair_1.into_keypair();

    let key_pair_2 = key_agreement.generate_keypair()?;
    let (public_key_2, private_key_2) = key_pair_2.into_keypair();

    // 4. Party 1 agrees on a shared secret using their private key and Party 2's public key.
    let shared_secret_1 = key_agreement.agree(&private_key_1, &public_key_2)?;

    // 5. Party 2 agrees on a shared secret using their private key and Party 1's public key.
    let shared_secret_2 = key_agreement.agree(&private_key_2, &public_key_1)?;

    // 6. Verify that the shared secrets match.
    assert_eq!(shared_secret_1, shared_secret_2);
    println!("Key agreement successful, shared secrets match!");

    Ok(())
}
```

### eXtendable-Output Function (XOF)

```rust
use seal_crypto_wrapper::prelude::*;
use seal_crypto_wrapper::error::Result;

fn main() -> Result<()> {
    // 1. Select a XOF algorithm.
    let algorithm = XofAlgorithm::build().shake128();

    // 2. Get the algorithm wrapper.
    let xof = algorithm.into_xof_wrapper();

    // 3. Define the input keying material, salt, and info.
    let ikm = b"input keying material";
    let salt = b"some salt";
    let info = b"some info";

    // 4. Create a XOF reader.
    let mut reader = xof.reader(ikm, Some(salt), Some(info))?;

    // 5. Read 32 bytes from the reader.
    let mut output1 = [0u8; 32];
    reader.read(&mut output1);

    // 6. Read another 64 bytes from the reader.
    let mut output2 = [0u8; 64];
    reader.read(&mut output2);

    // 7. Verify that the outputs are different.
    assert_ne!(&output1[..], &output2[..32]);
    println!("XOF successful, outputs are different as expected!");
    
    Ok(())
}
```

### Key-based Key Derivation (KDF)

```rust
use seal_crypto_wrapper::prelude::*;
use seal_crypto_wrapper::error::Result;

fn main() -> Result<()> {
    // 1. Select a key-based KDF algorithm.
    let algorithm = KdfAlgorithm::build().key().hkdf_sha256();

    // 2. Get the algorithm wrapper.
    let kdf = algorithm.into_kdf_key_wrapper();

    // 3. Define the input keying material, salt, and different infos.
    let ikm = b"input keying material";
    let salt = b"some salt";
    let info1 = b"info for key 1";
    let info2 = b"info for key 2";

    // 4. Derive the first key using info1.
    let key1 = kdf.derive(ikm, Some(salt), Some(info1), 32)?;

    // 5. Derive the second key using info2.
    let key2 = kdf.derive(ikm, Some(salt), Some(info2), 32)?;

    // 6. Verify that the derived keys are different.
    assert_ne!(key1, key2);
    println!("Key-based KDF successful, derived keys are different!");

    Ok(())
}
```

### Password-based Key Derivation (PBKDF)

```rust
use seal_crypto_wrapper::prelude::*;
use seal_crypto_wrapper::error::Result;

fn main() -> Result<()> {
    // 1. Select a password-based KDF algorithm.
    let algorithm = KdfAlgorithm::build().passwd().pbkdf2_sha256_default();

    // 2. Get the algorithm wrapper.
    let kdf = algorithm.into_kdf_password_wrapper();

    // 3. Define the password and different salts.
    let password = SecretBox::new(Box::from(b"my-secret-password".as_slice()));
    let salt1 = b"some salt";
    let salt2 = b"another salt";

    // 4. Derive the first key using salt1.
    let key1 = kdf.derive(&password, salt1, 32)?;

    // 5. Derive the second key using salt2.
    let key2 = kdf.derive(&password, salt2, 32)?;

    // 6. Verify that the derived keys are different.
    assert_ne!(key1, key2);
    println!("Password-based KDF successful, derived keys are different!");
    
    Ok(())
}
``` 