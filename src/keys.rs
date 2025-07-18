//! Type-safe cryptographic key management with algorithm binding.
//!
//! 具有算法绑定的类型安全密码密钥管理。
//!
//! ## Overview | 概述
//!
//! This module provides type-safe wrappers for cryptographic keys that bind key material
//! to specific algorithms. This design prevents common cryptographic misuse patterns,
//! such as using a key generated for one algorithm with a different algorithm.
//!
//! 此模块为密码密钥提供类型安全的包装器，将密钥材料绑定到特定算法。
//! 这种设计防止了常见的密码误用模式，例如将为一种算法生成的密钥用于不同的算法。
//!
//! ## Core Design Principles | 核心设计原则
//!
//! ### Algorithm Binding | 算法绑定
//!
//! Every typed key contains both the key material and metadata about the algorithm
//! used to generate it. This ensures that:
//!
//! 每个类型化密钥都包含密钥材料和用于生成它的算法的元数据。这确保了：
//!
//! - Keys can only be used with their intended algorithms
//! - Runtime verification prevents algorithm mismatches
//! - Serialization preserves algorithm information
//! - Type safety is maintained across operations
//!
//! - 密钥只能与其预期算法一起使用
//! - 运行时验证防止算法不匹配
//! - 序列化保留算法信息
//! - 在操作中保持类型安全
//!
//! ### Memory Safety | 内存安全
//!
//! All sensitive key material is handled using secure memory management:
//!
//! 所有敏感密钥材料都使用安全内存管理处理：
//!
//! - `Zeroizing<Vec<u8>>` for automatic memory clearing
//! - `SecretBox<[u8]>` for protected storage
//! - Constant-time operations where possible
//! - Secure random generation
//!
//! - `Zeroizing<Vec<u8>>` 用于自动内存清理
//! - `SecretBox<[u8]>` 用于受保护存储
//! - 尽可能使用常数时间操作
//! - 安全随机生成
//!
//! ## Key Categories | 密钥分类
//!
//! ### Symmetric Keys | 对称密钥
//! - **Untyped**: Raw key material without algorithm binding
//! - **Typed**: Algorithm-bound keys for AEAD ciphers
//!
//! ### Asymmetric Keys | 非对称密钥
//! - **KEM Keys**: For key encapsulation mechanisms
//! - **Signature Keys**: For digital signatures and verification
//! - **Key Agreement Keys**: For shared secret establishment
//!
//! ## Usage Patterns | 使用模式
//!
//! ### Key Generation | 密钥生成
//!
//! ```rust
//! use seal_crypto_wrapper::prelude::*;
//!
//! // Generate algorithm-bound symmetric key
//! #[cfg(feature = "symmetric")]
//! {
//!     let algorithm = SymmetricAlgorithm::build().aes256_gcm();
//!     let cipher = algorithm.into_symmetric_wrapper();
//!     let key = cipher.generate_typed_key()?;
//! }
//!
//! // Generate asymmetric key pair
//! #[cfg(feature = "asymmetric-signature")]
//! {
//!     let algorithm = AsymmetricAlgorithm::build().signature().ed25519();
//!     let signer = algorithm.into_signature_wrapper();
//!     let keypair = signer.generate_keypair()?;
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### Key Serialization | 密钥序列化
//!
//! ```rust
//! use seal_crypto_wrapper::prelude::*;
//! use serde::{Serialize, Deserialize};
//!
//! #[cfg(feature = "asymmetric-signature")]
//! {
//!     let keypair = AsymmetricAlgorithm::build().signature().ed25519().into_signature_wrapper().generate_keypair().unwrap();
//!     // Keys can be serialized with algorithm information
//!     let key_json = serde_json::to_string(&keypair).unwrap();
//!     let restored_keypair: seal_crypto_wrapper::keys::asymmetric::signature::TypedSignatureKeyPair = serde_json::from_str(&key_json).unwrap();
//!     println!("Successfully serialized and deserialized signature keypair");
//! }
//! ```
//!
//! ## Security Considerations | 安全考虑
//!
//! - **Key Lifecycle**: Generate, use, and destroy keys securely
//! - **Algorithm Verification**: Always verify algorithm compatibility
//! - **Secure Storage**: Use appropriate protection for key material
//! - **Key Rotation**: Implement regular key rotation policies
//!
//! - **密钥生命周期**: 安全地生成、使用和销毁密钥
//! - **算法验证**: 始终验证算法兼容性
//! - **安全存储**: 为密钥材料使用适当的保护
//! - **密钥轮换**: 实施定期密钥轮换策略

// Asymmetric key types and management | 非对称密钥类型和管理
#[cfg(any(feature = "asymmetric-kem", feature = "asymmetric-signature", feature = "asymmetric-key-agreement"))]
pub mod asymmetric;

// Symmetric key types and management | 对称密钥类型和管理
#[cfg(feature = "symmetric")]
pub mod symmetric;
