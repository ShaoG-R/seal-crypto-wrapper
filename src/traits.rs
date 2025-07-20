//! Core traits for type-safe cryptographic algorithm specification.
//!
//! 用于类型安全密码算法规范的核心 trait。
//!
//! ## Overview | 概述
//!
//! This module defines the fundamental traits that enable type-safe cryptographic operations
//! in the seal-crypto-wrapper library. These traits provide object-safe interfaces for
//! different cryptographic primitives while maintaining algorithm-specific type information.
//!
//! 此模块定义了在 seal-crypto-wrapper 库中启用类型安全密码操作的基本 trait。
//! 这些 trait 为不同的密码原语提供对象安全接口，同时保持算法特定的类型信息。
//!
//! ## Design Principles | 设计原则
//!
//! ### Object Safety | 对象安全性
//!
//! All traits in this module are designed to be object-safe, allowing them to be used
//! as trait objects (`Box<dyn Trait>`). This enables runtime polymorphism while
//! maintaining compile-time type safety.
//!
//! 此模块中的所有 trait 都设计为对象安全的，允许它们用作 trait 对象 (`Box<dyn Trait>`)。
//! 这在保持编译时类型安全的同时启用了运行时多态性。
//!
//! ### Algorithm Binding | 算法绑定
//!
//! Each trait includes an `algorithm()` method that returns the specific algorithm
//! enum variant. This allows runtime verification that keys and operations match
//! the expected algorithm.
//!
//! 每个 trait 都包含一个 `algorithm()` 方法，返回特定的算法枚举变体。
//! 这允许运行时验证密钥和操作是否匹配预期的算法。
//!
//! ### Memory Safety | 内存安全
//!
//! Sensitive data is handled using `Zeroizing<Vec<u8>>` and `SecretBox<[u8]>`
//! to ensure proper cleanup and prevent accidental exposure.
//!
//! 敏感数据使用 `Zeroizing<Vec<u8>>` 和 `SecretBox<[u8]>` 处理，
//! 以确保正确清理并防止意外暴露。
//!
//! ## Trait Categories | Trait 分类
//!
//! - **Symmetric Cryptography**: `SymmetricAlgorithmTrait` for AEAD ciphers
//! - **Asymmetric KEM**: `KemAlgorithmTrait` for key encapsulation mechanisms
//! - **Digital Signatures**: `SignatureAlgorithmTrait` for signing and verification
//! - **Key Agreement**: `KeyAgreementAlgorithmTrait` for shared secret derivation
//! - **Key Derivation**: `KdfKeyAlgorithmTrait`, `KdfPasswordAlgorithmTrait` for key derivation
//! - **Extendable Output**: `XofAlgorithmTrait` for variable-length output functions
//!
//! - **对称密码学**: `SymmetricAlgorithmTrait` 用于 AEAD 密码
//! - **非对称 KEM**: `KemAlgorithmTrait` 用于密钥封装机制
//! - **数字签名**: `SignatureAlgorithmTrait` 用于签名和验证
//! - **密钥协商**: `KeyAgreementAlgorithmTrait` 用于共享密钥派生
//! - **密钥派生**: `KdfKeyAlgorithmTrait`, `KdfPasswordAlgorithmTrait` 用于密钥派生
//! - **可扩展输出**: `XofAlgorithmTrait` 用于可变长度输出函数
//!
//! ## Macro Utilities | 宏工具
//!
//! The `impl_trait_for_box!` macro automatically implements traits for `Box<dyn Trait>`
//! types, enabling seamless use of trait objects with the same interface as concrete types.
//!
//! `impl_trait_for_box!` 宏自动为 `Box<dyn Trait>` 类型实现 trait，
//! 使 trait 对象能够与具体类型使用相同的接口。

#[cfg(feature = "asymmetric-key-agreement")]
use crate::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;
#[cfg(feature = "asymmetric-signature")]
use crate::algorithms::asymmetric::signature::SignatureAlgorithm;
#[cfg(feature = "asymmetric-key-agreement")]
use crate::keys::asymmetric::key_agreement::{
    TypedKeyAgreementKeyPair, TypedKeyAgreementPrivateKey, TypedKeyAgreementPublicKey,
};
#[cfg(feature = "asymmetric-signature")]
use crate::keys::asymmetric::signature::{
    TypedSignatureKeyPair, TypedSignaturePrivateKey, TypedSignaturePublicKey,
};
#[cfg(feature = "asymmetric-kem")]
use {
    crate::algorithms::asymmetric::kem::KemAlgorithm,
    crate::keys::asymmetric::kem::{
        EncapsulatedKey, SharedSecret, TypedKemKeyPair, TypedKemPrivateKey, TypedKemPublicKey,
    },
};
#[cfg(feature = "kdf")]
use {
    crate::algorithms::kdf::key::KdfKeyAlgorithm,
    crate::algorithms::kdf::passwd::KdfPasswordAlgorithm,
};
#[cfg(feature = "symmetric")]
use {
    crate::algorithms::symmetric::SymmetricAlgorithm,
    crate::keys::symmetric::{SymmetricKey as UntypedSymmetricKey, TypedSymmetricKey},
};
#[cfg(feature = "xof")]
use {crate::algorithms::xof::XofAlgorithm, crate::wrappers::xof::XofReaderWrapper};
#[cfg(any(
    feature = "symmetric",
    feature = "asymmetric-kem",
    feature = "kdf",
    feature = "xof",
    feature = "asymmetric-signature",
    feature = "asymmetric-key-agreement"
))]
use {
    crate::error::Result,
    seal_crypto::{secrecy::SecretBox, zeroize::Zeroizing},
};

/// Macro for automatically implementing traits for `Box<dyn Trait>` types.
///
/// 用于自动为 `Box<dyn Trait>` 类型实现 trait 的宏。
///
/// ## Purpose | 目的
///
/// This macro generates implementations that allow `Box<dyn Trait>` to be used
/// seamlessly as if it were a concrete type implementing the trait. It handles
/// method delegation and provides automatic `Clone` implementation.
///
/// 此宏生成实现，允许 `Box<dyn Trait>` 像具体类型一样无缝使用。
/// 它处理方法委托并提供自动的 `Clone` 实现。
///
/// ## Syntax | 语法
///
/// ```ignore
/// impl_trait_for_box!(TraitName {
///     ref fn method_name(&self, arg: Type) -> ReturnType;
///     self fn consuming_method(self, arg: Type) -> ReturnType;
/// }, clone_method_name);
/// ```
///
/// ## Method Types | 方法类型
///
/// - `ref fn`: Methods that take `&self` - delegated to the inner trait object
/// - `self fn`: Methods that consume `self` - may have custom implementations
///
/// - `ref fn`: 接受 `&self` 的方法 - 委托给内部 trait 对象
/// - `self fn`: 消费 `self` 的方法 - 可能有自定义实现
///
/// ## Examples | 示例
///
/// ```ignore
/// impl_trait_for_box!(SymmetricAlgorithmTrait {
///     ref fn encrypt(&self, key: &Key, data: &[u8]) -> Result<Vec<u8>>;
///     ref fn decrypt(&self, key: &Key, data: &[u8]) -> Result<Vec<u8>>;
/// }, clone_box_symmetric);
/// ```
#[allow(unused_macros)]
macro_rules! impl_trait_for_box {
    // Internal recursive rules for TT muncher
    (
        @impl,
        $trait:ident,
        $clone_box_name:ident,
        { }, // no more methods
        { $($impls:tt)* } // accumulated impls
    ) => {
        impl Clone for Box<dyn $trait> {
            fn clone(&self) -> Self {
                self.$clone_box_name()
            }
        }

        impl $trait for Box<dyn $trait> {
            $($impls)*
        }
    };

    // Munch a `ref fn` with generics
    (
        @impl,
        $trait:ident,
        $clone_box_name:ident,
        {
            ref fn $method:ident< $($lt:lifetime),+ >(&self, $($arg:ident: $ty:ty),*) -> $ret:ty;
            $($rest:tt)*
        },
        { $($impls:tt)* }
    ) => {
        impl_trait_for_box! {
            @impl,
            $trait,
            $clone_box_name,
            { $($rest)* },
            {
                $($impls)*
                fn $method< $($lt),+ >(&self, $($arg: $ty),*) -> $ret {
                    self.as_ref().$method($($arg),*)
                }
            }
        }
    };

    // Munch a `ref fn`
    (
        @impl,
        $trait:ident,
        $clone_box_name:ident,
        {
            ref fn $method:ident(&self, $($arg:ident: $ty:ty),*) -> $ret:ty;
            $($rest:tt)*
        },
        { $($impls:tt)* }
    ) => {
        impl_trait_for_box! {
            @impl,
            $trait,
            $clone_box_name,
            { $($rest)* },
            {
                $($impls)*
                fn $method(&self, $($arg: $ty),*) -> $ret {
                    self.as_ref().$method($($arg),*)
                }
            }
        }
    };

    // Munch a `self fn` with custom implementation
    (
        @impl,
        $trait:ident,
        $clone_box_name:ident,
        {
            self fn $method:ident(self, $($arg:ident: $ty:ty),*) -> $ret:ty { $($body:tt)+ };
            $($rest:tt)*
        },
        { $($impls:tt)* }
    ) => {
        impl_trait_for_box! {
            @impl,
            $trait,
            $clone_box_name,
            { $($rest)* },
            {
                $($impls)*
                fn $method(self, $($arg: $ty),*) -> $ret {
                    $($body)+
                }
            }
        }
    };

    // Munch a `self fn` with default `self` return
    (
        @impl,
        $trait:ident,
        $clone_box_name:ident,
        {
            self fn $method:ident(self, $($arg:ident: $ty:ty),*) -> $ret:ty;
            $($rest:tt)*
        },
        { $($impls:tt)* }
    ) => {
        impl_trait_for_box! {
            @impl,
            $trait,
            $clone_box_name,
            { $($rest)* },
            {
                $($impls)*
                fn $method(self, $($arg: $ty),*) -> $ret {
                    self
                }
            }
        }
    };

    // Public entry point
    ($trait:ident { $($methods:tt)* }, $clone_box_name:ident) => {
        impl_trait_for_box! {
            @impl,
            $trait,
            $clone_box_name,
            { $($methods)* },
            { }
        }
    };
}

/// Trait for symmetric encryption algorithms with Authenticated Encryption with Associated Data (AEAD).
///
/// 用于带关联数据认证加密 (AEAD) 的对称加密算法 trait。
///
/// ## Overview | 概述
///
/// This trait provides a unified interface for symmetric encryption algorithms that support
/// AEAD (Authenticated Encryption with Associated Data). All methods are object-safe,
/// allowing the trait to be used as a trait object.
///
/// 此 trait 为支持 AEAD（带关联数据的认证加密）的对称加密算法提供统一接口。
/// 所有方法都是对象安全的，允许将 trait 用作 trait 对象。
///
/// ## Supported Algorithms | 支持的算法
///
/// - AES-128-GCM, AES-256-GCM
/// - ChaCha20-Poly1305, XChaCha20-Poly1305
///
/// ## Security Guarantees | 安全保证
///
/// - **Confidentiality**: Plaintext is encrypted and cannot be recovered without the key
/// - **Authenticity**: Ciphertext integrity is verified during decryption
/// - **Associated Data**: Additional data can be authenticated without encryption
///
/// - **机密性**: 明文被加密，没有密钥无法恢复
/// - **真实性**: 解密时验证密文完整性
/// - **关联数据**: 可以在不加密的情况下认证附加数据
///
/// ## Usage Guidelines | 使用指南
///
/// - Always use a unique nonce for each encryption operation
/// - Never reuse nonce-key pairs
/// - Use cryptographically secure random number generation for nonces
/// - Consider using associated data for context binding
///
/// - 每次加密操作都使用唯一的 nonce
/// - 永远不要重复使用 nonce-密钥对
/// - 为 nonce 使用密码学安全的随机数生成
/// - 考虑使用关联数据进行上下文绑定
#[cfg(feature = "symmetric")]
pub trait SymmetricAlgorithmTrait: Send + Sync + 'static {
    /// Encrypts plaintext with optional associated data.
    ///
    /// 使用可选关联数据加密明文。
    ///
    /// # Arguments | 参数
    ///
    /// * `key` - Typed symmetric key bound to this algorithm | 绑定到此算法的类型化对称密钥
    /// * `plaintext` - Data to encrypt | 要加密的数据
    /// * `nonce` - Unique number used once (must be unique per key) | 一次性使用的唯一数字（每个密钥必须唯一）
    /// * `aad` - Optional associated data to authenticate | 要认证的可选关联数据
    ///
    /// # Returns | 返回值
    ///
    /// Encrypted ciphertext with authentication tag appended.
    ///
    /// 附加了认证标签的加密密文。
    ///
    /// # Errors | 错误
    ///
    /// - Key algorithm mismatch | 密钥算法不匹配
    /// - Invalid nonce length | 无效的 nonce 长度
    /// - Encryption failure | 加密失败
    ///
    /// # Security | 安全性
    ///
    /// The nonce MUST be unique for each encryption with the same key.
    /// Reusing nonces can lead to catastrophic security failures.
    ///
    /// 对于同一密钥的每次加密，nonce 必须是唯一的。
    /// 重复使用 nonce 可能导致灾难性的安全故障。
    fn encrypt(
        &self,
        plaintext: &[u8],
        key: &TypedSymmetricKey,
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    /// Encrypts plaintext into a provided buffer.
    ///
    /// 将明文加密到提供的缓冲区中。
    ///
    /// This is a zero-allocation variant of `encrypt` that writes directly
    /// to the provided output buffer.
    ///
    /// 这是 `encrypt` 的零分配变体，直接写入提供的输出缓冲区。
    ///
    /// # Arguments | 参数
    ///
    /// * `output` - Buffer to write encrypted data (must be large enough) | 写入加密数据的缓冲区（必须足够大）
    ///
    /// # Returns | 返回值
    ///
    /// Number of bytes written to the output buffer.
    ///
    /// 写入输出缓冲区的字节数。
    fn encrypt_to_buffer(
        &self,
        plaintext: &[u8],
        output: &mut [u8],
        key: &TypedSymmetricKey,
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<usize>;

    /// Decrypts ciphertext and verifies authentication.
    ///
    /// 解密密文并验证认证。
    ///
    /// # Arguments | 参数
    /// * `ciphertext` - Encrypted data with authentication tag | 带认证标签的加密数据
    /// * `key` - Typed symmetric key bound to this algorithm | 绑定到此算法的类型化对称密钥
    /// * `nonce` - Same nonce used for encryption | 用于加密的相同 nonce
    /// * `aad` - Same associated data used for encryption | 用于加密的相同关联数据
    ///
    /// # Returns | 返回值
    ///
    /// Decrypted plaintext if authentication succeeds.
    ///
    /// 如果认证成功则返回解密的明文。
    ///
    /// # Errors | 错误
    ///
    /// - Key algorithm mismatch | 密钥算法不匹配
    /// - Authentication failure (tampered data) | 认证失败（数据被篡改）
    /// - Invalid ciphertext format | 无效的密文格式
    ///
    /// # Security | 安全性
    ///
    /// Authentication failure indicates the ciphertext has been tampered with
    /// or the wrong key/nonce/AAD was used. Never use unauthenticated data.
    ///
    /// 认证失败表示密文已被篡改或使用了错误的密钥/nonce/AAD。
    /// 永远不要使用未经认证的数据。
    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &TypedSymmetricKey,
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    /// Decrypts ciphertext into a provided buffer.
    ///
    /// 将密文解密到提供的缓冲区中。
    ///
    /// Zero-allocation variant of `decrypt` that writes directly to the output buffer.
    ///
    /// `decrypt` 的零分配变体，直接写入输出缓冲区。
    ///
    /// # Returns | 返回值
    ///
    /// Number of bytes written to the output buffer.
    ///
    /// 写入输出缓冲区的字节数。
    fn decrypt_to_buffer(
        &self,
        ciphertext: &[u8],
        output: &mut [u8],
        key: &TypedSymmetricKey,
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<usize>;

    /// Generates a new typed symmetric key for this algorithm.
    ///
    /// 为此算法生成新的类型化对称密钥。
    ///
    /// The generated key is cryptographically bound to this specific algorithm
    /// and cannot be used with other algorithms.
    ///
    /// 生成的密钥在密码学上绑定到此特定算法，不能与其他算法一起使用。
    ///
    /// # Returns | 返回值
    ///
    /// A new typed symmetric key with proper algorithm binding.
    ///
    /// 具有正确算法绑定的新类型化对称密钥。
    fn generate_typed_key(&self) -> Result<TypedSymmetricKey>;

    /// Generates a new untyped symmetric key.
    ///
    /// 生成新的非类型化对称密钥。
    ///
    /// This generates raw key material without algorithm binding.
    /// Use `generate_typed_key` for type-safe operations.
    ///
    /// 这生成没有算法绑定的原始密钥材料。
    /// 使用 `generate_typed_key` 进行类型安全操作。
    fn generate_untyped_key(&self) -> Result<UntypedSymmetricKey>;

    /// Returns the algorithm identifier.
    ///
    /// 返回算法标识符。
    ///
    /// Used for runtime algorithm verification and key compatibility checking.
    ///
    /// 用于运行时算法验证和密钥兼容性检查。
    fn algorithm(&self) -> SymmetricAlgorithm;

    /// Returns the key size in bytes for this algorithm.
    ///
    /// 返回此算法的密钥大小（字节）。
    ///
    /// # Examples | 示例
    ///
    /// - AES-128: 16 bytes
    /// - AES-256: 32 bytes
    /// - ChaCha20: 32 bytes
    fn key_size(&self) -> usize;

    /// Returns the nonce size in bytes for this algorithm.
    ///
    /// 返回此算法的 nonce 大小（字节）。
    ///
    /// # Examples | 示例
    ///
    /// - AES-GCM: 12 bytes (96 bits)
    /// - ChaCha20-Poly1305: 12 bytes
    /// - XChaCha20-Poly1305: 24 bytes
    fn nonce_size(&self) -> usize;

    /// Returns the authentication tag size in bytes.
    ///
    /// 返回认证标签大小（字节）。
    ///
    /// All supported AEAD algorithms use 16-byte (128-bit) tags.
    ///
    /// 所有支持的 AEAD 算法都使用 16 字节（128 位）标签。
    fn tag_size(&self) -> usize;

    /// Converts the algorithm into a boxed trait object.
    ///
    /// 将算法转换为 boxed trait 对象。
    ///
    /// Consumes `self` and returns a heap-allocated trait object.
    /// Useful for storing different algorithm types in collections.
    ///
    /// 消费 `self` 并返回堆分配的 trait 对象。
    /// 用于在集合中存储不同的算法类型。
    fn into_symmetric_boxed(self) -> Box<dyn SymmetricAlgorithmTrait>;

    /// Creates a cloned boxed trait object.
    ///
    /// 创建克隆的 boxed trait 对象。
    ///
    /// Returns a new heap-allocated trait object with the same algorithm.
    /// Required for implementing `Clone` on `Box<dyn SymmetricAlgorithmTrait>`.
    ///
    /// 返回具有相同算法的新堆分配 trait 对象。
    /// 在 `Box<dyn SymmetricAlgorithmTrait>` 上实现 `Clone` 所必需的。
    fn clone_box_symmetric(&self) -> Box<dyn SymmetricAlgorithmTrait>;
}

#[cfg(feature = "symmetric")]
impl_trait_for_box!(SymmetricAlgorithmTrait {
    ref fn encrypt(&self, plaintext: &[u8], key: &TypedSymmetricKey, nonce: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>>;
    ref fn encrypt_to_buffer(&self, plaintext: &[u8], output: &mut [u8], key: &TypedSymmetricKey, nonce: &[u8], aad: Option<&[u8]>) -> Result<usize>;
    ref fn decrypt(&self, ciphertext: &[u8], key: &TypedSymmetricKey, nonce: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>>;
    ref fn decrypt_to_buffer(&self, ciphertext: &[u8], output: &mut [u8], key: &TypedSymmetricKey, nonce: &[u8], aad: Option<&[u8]>) -> Result<usize>;
    ref fn generate_typed_key(&self,) -> Result<TypedSymmetricKey>;
    ref fn generate_untyped_key(&self,) -> Result<UntypedSymmetricKey>;
    ref fn algorithm(&self,) -> SymmetricAlgorithm;
    ref fn key_size(&self,) -> usize;
    ref fn nonce_size(&self,) -> usize;
    ref fn tag_size(&self,) -> usize;
    self fn into_symmetric_boxed(self,) -> Box<dyn SymmetricAlgorithmTrait>;
    ref fn clone_box_symmetric(&self,) -> Box<dyn SymmetricAlgorithmTrait>;
}, clone_box_symmetric);

/// Trait to provide the details for a specific asymmetric algorithm.
/// The implementor of this trait is the scheme itself.
///
/// 用于提供特定非对称算法详细信息的 trait。
/// 该 trait 的实现者是算法方案本身。
#[cfg(feature = "asymmetric-kem")]
pub trait KemAlgorithmTrait: Send + Sync + 'static {
    /// Returns the algorithm enum.
    ///
    /// 返回算法枚举。
    fn algorithm(&self) -> KemAlgorithm;

    /// Encapsulates a key.
    ///
    /// 封装一个密钥。
    fn encapsulate_key(
        &self,
        public_key: &TypedKemPublicKey,
    ) -> Result<(SharedSecret, EncapsulatedKey)>;

    /// Decapsulates a key.
    ///
    /// 解封装一个密钥。
    fn decapsulate_key(
        &self,
        private_key: &TypedKemPrivateKey,
        encapsulated_key: &EncapsulatedKey,
    ) -> Result<SharedSecret>;

    fn generate_keypair(&self) -> Result<TypedKemKeyPair>;

    /// Clones the algorithm.
    ///
    /// 克隆算法。
    fn clone_box_asymmetric(&self) -> Box<dyn KemAlgorithmTrait>;

    fn into_asymmetric_boxed(self) -> Box<dyn KemAlgorithmTrait>;
}

#[cfg(feature = "asymmetric-kem")]
impl_trait_for_box!(KemAlgorithmTrait {
    ref fn clone_box_asymmetric(&self,) -> Box<dyn KemAlgorithmTrait>;
    ref fn algorithm(&self,) -> KemAlgorithm;
    ref fn encapsulate_key(&self, public_key: &TypedKemPublicKey) -> Result<(SharedSecret, EncapsulatedKey)>;
    ref fn decapsulate_key(&self, private_key: &TypedKemPrivateKey, encapsulated_key: &EncapsulatedKey) -> Result<SharedSecret>;
    ref fn generate_keypair(&self,) -> Result<TypedKemKeyPair>;
    self fn into_asymmetric_boxed(self,) -> Box<dyn KemAlgorithmTrait>;
}, clone_box_asymmetric);

#[cfg(feature = "kdf")]
pub trait KdfKeyAlgorithmTrait: Send + Sync + 'static {
    fn derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>>;

    fn algorithm(&self) -> KdfKeyAlgorithm;

    fn clone_box(&self) -> Box<dyn KdfKeyAlgorithmTrait>;
}

#[cfg(feature = "kdf")]
impl_trait_for_box!(KdfKeyAlgorithmTrait {
    ref fn clone_box(&self,) -> Box<dyn KdfKeyAlgorithmTrait>;
    ref fn derive(&self, ikm: &[u8], salt: Option<&[u8]>, info: Option<&[u8]>, output_len: usize) -> Result<Zeroizing<Vec<u8>>>;
    ref fn algorithm(&self,) -> KdfKeyAlgorithm;
}, clone_box);

#[cfg(feature = "kdf")]
pub trait KdfPasswordAlgorithmTrait: Send + Sync + 'static {
    fn derive(
        &self,
        password: &SecretBox<[u8]>,
        salt: &[u8],
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>>;

    fn algorithm(&self) -> KdfPasswordAlgorithm;

    fn clone_box(&self) -> Box<dyn KdfPasswordAlgorithmTrait>;
}

#[cfg(feature = "kdf")]
impl_trait_for_box!(KdfPasswordAlgorithmTrait {
    ref fn clone_box(&self,) -> Box<dyn KdfPasswordAlgorithmTrait>;
    ref fn derive(&self, password: &SecretBox<[u8]>, salt: &[u8], output_len: usize) -> Result<Zeroizing<Vec<u8>>>;
    ref fn algorithm(&self,) -> KdfPasswordAlgorithm;
}, clone_box);

#[cfg(feature = "xof")]
pub trait XofAlgorithmTrait: Send + Sync + 'static {
    fn reader<'a>(
        &self,
        ikm: &'a [u8],
        salt: Option<&'a [u8]>,
        info: Option<&'a [u8]>,
    ) -> Result<XofReaderWrapper<'a>>;
    fn clone_box(&self) -> Box<dyn XofAlgorithmTrait>;
    fn algorithm(&self) -> XofAlgorithm;
}

#[cfg(feature = "xof")]
impl_trait_for_box!(XofAlgorithmTrait {
    ref fn reader<'a>(&self, ikm: &'a [u8], salt: Option<&'a [u8]>, info: Option<&'a [u8]>) -> Result<XofReaderWrapper<'a>>;
    ref fn algorithm(&self,) -> XofAlgorithm;
    ref fn clone_box(&self,) -> Box<dyn XofAlgorithmTrait>;
}, clone_box);

#[cfg(feature = "asymmetric-signature")]
pub trait SignatureAlgorithmTrait: Send + Sync + 'static {
    fn sign(&self, message: &[u8], key: &TypedSignaturePrivateKey) -> Result<Vec<u8>>;
    fn verify(
        &self,
        message: &[u8],
        key: &TypedSignaturePublicKey,
        signature: Vec<u8>,
    ) -> Result<()>;
    fn generate_keypair(&self) -> Result<TypedSignatureKeyPair>;
    fn clone_box(&self) -> Box<dyn SignatureAlgorithmTrait>;
    fn algorithm(&self) -> SignatureAlgorithm;
}

#[cfg(feature = "asymmetric-signature")]
impl_trait_for_box!(SignatureAlgorithmTrait {
    ref fn sign(&self, message: &[u8], key: &TypedSignaturePrivateKey) -> Result<Vec<u8>>;
    ref fn verify(&self, message: &[u8], key: &TypedSignaturePublicKey, signature: Vec<u8>) -> Result<()>;
    ref fn generate_keypair(&self,) -> Result<TypedSignatureKeyPair>;
    ref fn clone_box(&self,) -> Box<dyn SignatureAlgorithmTrait>;
    ref fn algorithm(&self,) -> SignatureAlgorithm;
}, clone_box);

#[cfg(feature = "asymmetric-key-agreement")]
pub trait KeyAgreementAlgorithmTrait: Send + Sync + 'static {
    fn agree(
        &self,
        sk: &TypedKeyAgreementPrivateKey,
        pk: &TypedKeyAgreementPublicKey,
    ) -> Result<Zeroizing<Vec<u8>>>;
    fn generate_keypair(&self) -> Result<TypedKeyAgreementKeyPair>;
    fn clone_box(&self) -> Box<dyn KeyAgreementAlgorithmTrait>;
    fn algorithm(&self) -> KeyAgreementAlgorithm;
}

#[cfg(feature = "asymmetric-key-agreement")]
impl_trait_for_box!(KeyAgreementAlgorithmTrait {
    ref fn agree(&self, sk: &TypedKeyAgreementPrivateKey, pk: &TypedKeyAgreementPublicKey) -> Result<Zeroizing<Vec<u8>>>;
    ref fn generate_keypair(&self,) -> Result<TypedKeyAgreementKeyPair>;
    ref fn clone_box(&self,) -> Box<dyn KeyAgreementAlgorithmTrait>;
    ref fn algorithm(&self,) -> KeyAgreementAlgorithm;
}, clone_box);
