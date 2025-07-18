//! # Seal Crypto Wrapper
//!
//! A high-level, misuse-resistant cryptographic wrapper library for Rust.
//!
//! 一个高级别、防误用的 Rust 加密包装库。
//!
//! ## Overview | 概述
//!
//! This library provides a safer and more user-friendly API for cryptographic operations
//! by tightly binding algorithm information with keys themselves. This design prevents
//! common cryptographic misuse patterns, such as using a key generated for one algorithm
//! with a different algorithm.
//!
//! 本库通过将算法信息与密钥本身紧密绑定，为加密操作提供更安全、更用户友好的 API。
//! 这种设计可以防止常见的加密误用模式，例如将为一种算法生成的密钥用于不同的算法。
//!
//! ## Core Design Philosophy | 核心设计理念
//!
//! ### Type Safety | 类型安全
//!
//! - **Typed Keys**: Each cryptographic primitive (symmetric encryption, signatures, KEM, etc.)
//!   has dedicated key types like `TypedSymmetricKey` and `TypedSignatureKeyPair`.
//! - **Algorithm Binding**: Every typed key is bound to the specific algorithm used to create it.
//! - **Runtime Verification**: Before any cryptographic operation, the library automatically
//!   verifies that the key's bound algorithm matches the current operation's algorithm.
//!
//! - **类型化密钥**：每种加密原语（对称加密、签名、KEM 等）都有专用的密钥类型，
//!   如 `TypedSymmetricKey` 和 `TypedSignatureKeyPair`。
//! - **算法绑定**：每个类型化密钥都绑定到用于创建它的特定算法。
//! - **运行时验证**：在任何加密操作之前，库会自动验证密钥绑定的算法是否与当前操作的算法匹配。
//!
//! ### Convenience Features | 便利功能
//!
//! - **Serialization Support**: Key structures can be directly serialized/deserialized using `serde`.
//! - **Unified Builder API**: Fluent, chainable API for selecting and constructing algorithm instances.
//! - **Comprehensive Error Handling**: Clear error types with detailed information.
//!
//! - **序列化支持**：密钥结构可以直接使用 `serde` 进行序列化/反序列化。
//! - **统一构建器 API**：用于选择和构建算法实例的流畅链式 API。
//! - **全面的错误处理**：具有详细信息的清晰错误类型。
//!
//! ## Quick Start | 快速开始
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! seal-crypto-wrapper = { version = "0.1", features = ["full"] }
//! ```
//!
//! ### Symmetric Encryption Example | 对称加密示例
//!
//! ```rust
//! use seal_crypto_wrapper::prelude::*;
//! use seal_crypto_wrapper::error::Result;
//!
//! fn main() -> Result<()> {
//!     // 1. Select a symmetric algorithm | 选择对称算法
//!     let algorithm = SymmetricAlgorithm::build().aes256_gcm();
//!
//!     // 2. Get the algorithm wrapper | 获取算法包装器
//!     let cipher = algorithm.into_symmetric_wrapper();
//!
//!     // 3. Generate a typed key | 生成类型化密钥
//!     let key = cipher.generate_typed_key()?;
//!
//!     // 4. Encrypt data | 加密数据
//!     let plaintext = b"Hello, World!";
//!     let nonce = vec![0u8; cipher.nonce_size()]; // Use random nonce in production
//!     let aad = b"Additional Authenticated Data";
//!     let ciphertext = cipher.encrypt(plaintext, &key, &nonce,Some(aad))?;
//!
//!     // 5. Decrypt data | 解密数据
//!     let decrypted = cipher.decrypt(&ciphertext, &key, &nonce, Some(aad))?;
//!     assert_eq!(plaintext, &decrypted[..]);
//!
//!     Ok(())
//! }
//! ```
//!
//! ### Digital Signature Example | 数字签名示例
//!
//! ```rust
//! use seal_crypto_wrapper::prelude::*;
//! use seal_crypto_wrapper::error::Result;
//!
//! fn main() -> Result<()> {
//!     // 1. Select a signature algorithm | 选择签名算法
//!     let algorithm = AsymmetricAlgorithm::build().signature().ed25519();
//!
//!     // 2. Get the algorithm wrapper | 获取算法包装器
//!     let signature_scheme = algorithm.into_signature_wrapper();
//!
//!     // 3. Generate a key pair | 生成密钥对
//!     let key_pair = signature_scheme.generate_keypair()?;
//!     let (public_key, private_key) = key_pair.into_keypair();
//!
//!     // 4. Sign a message | 签名消息
//!     let message = b"Important message";
//!     let signature = signature_scheme.sign(message, &private_key)?;
//!
//!     // 5. Verify the signature | 验证签名
//!     signature_scheme.verify(message, &public_key, signature)?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Feature Flags | 功能标志
//!
//! This library uses feature flags to enable specific cryptographic algorithms:
//!
//! 本库使用功能标志来启用特定的加密算法：
//!
//! - `symmetric` - Symmetric encryption algorithms (AES-GCM, ChaCha20-Poly1305)
//! - `asymmetric-kem` - Key Encapsulation Mechanisms (RSA, Kyber)
//! - `asymmetric-signature` - Digital signatures (Ed25519, ECDSA, Dilithium)
//! - `asymmetric-key-agreement` - Key agreement protocols (ECDH)
//! - `kdf` - Key Derivation Functions (HKDF, PBKDF2, Argon2)
//! - `xof` - Extendable Output Functions (SHAKE)
//! - `full` - Enable all features
//!
//! ## Security Considerations | 安全考虑
//!
//! - **Key Management**: Always use secure random number generation for keys and nonces.
//! - **Algorithm Selection**: Choose algorithms appropriate for your security requirements.
//! - **Side-Channel Attacks**: Be aware of timing attacks and other side-channel vulnerabilities.
//! - **Post-Quantum Cryptography**: Consider using post-quantum algorithms (Kyber, Dilithium) for long-term security.
//!
//! - **密钥管理**：始终为密钥和随机数使用安全的随机数生成。
//! - **算法选择**：选择适合您安全要求的算法。
//! - **侧信道攻击**：注意时序攻击和其他侧信道漏洞。
//! - **后量子密码学**：考虑使用后量子算法（Kyber、Dilithium）以获得长期安全性。
//!
//! ## Module Organization | 模块组织
//!
//! - [`algorithms`] - Algorithm definitions and builders | 算法定义和构建器
//! - [`keys`] - Typed key structures | 类型化密钥结构
//! - [`wrappers`] - Algorithm implementation wrappers | 算法实现包装器
//! - [`traits`] - Core traits for type safety | 类型安全的核心 trait
//! - [`error`] - Error types and handling | 错误类型和处理
//! - [`prelude`] - Commonly used imports | 常用导入

pub mod algorithms;
pub mod error;
pub mod keys;
pub mod prelude;
pub mod traits;
pub mod wrappers;

/// Re-export of the `bincode` crate for serialization convenience.
///
/// 重新导出 `bincode` crate 以便于序列化。
///
/// This allows users to access `bincode` functionality without adding it as a separate dependency.
/// Useful for custom serialization scenarios beyond the built-in `serde` support.
///
/// 这允许用户访问 `bincode` 功能，而无需将其添加为单独的依赖项。
/// 对于超出内置 `serde` 支持的自定义序列化场景很有用。
pub use ::bincode;