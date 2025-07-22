//! Asymmetric (public-key) cryptography key types and management.
//!
//! 非对称（公钥）密码学密钥类型和管理。
//!
//! ## Overview | 概述
//!
//! This module provides type-safe wrappers for asymmetric cryptographic keys,
//! supporting multiple cryptographic primitives including key encapsulation mechanisms (KEM),
//! digital signatures, and key agreement protocols. Each key type is bound to its
//! specific algorithm to prevent misuse.
//!
//! 此模块为非对称密码密钥提供类型安全的包装器，
//! 支持多种密码原语，包括密钥封装机制 (KEM)、数字签名和密钥协商协议。
//! 每种密钥类型都绑定到其特定算法以防止误用。
//!
//! ## Key Categories | 密钥分类
//!
//! ### Key Encapsulation Mechanism (KEM) | 密钥封装机制
//! - **RSA KEM**: Traditional public-key cryptosystem
//! - **Kyber**: Post-quantum lattice-based KEM (NIST standardized)
//!
//! ### Digital Signatures | 数字签名
//! - **Ed25519**: High-performance Edwards curve signatures
//! - **ECDSA P-256**: NIST standard elliptic curve signatures
//! - **Dilithium**: Post-quantum lattice-based signatures (NIST standardized)
//!
//! ### Key Agreement | 密钥协商
//! - **ECDH P-256**: Elliptic Curve Diffie-Hellman key agreement
//!
//! ## Design Principles | 设计原则
//!
//! ### Algorithm Binding | 算法绑定
//! Each typed key contains both the key material and metadata about the algorithm
//! used to generate it, ensuring keys can only be used with their intended algorithms.
//!
//! 每个类型化密钥都包含密钥材料和用于生成它的算法的元数据，
//! 确保密钥只能与其预期算法一起使用。
//!
//! ### Memory Safety | 内存安全
//! All private key material is stored in `Zeroizing<Vec<u8>>` containers that
//! automatically clear sensitive data when dropped.
//!
//! 所有私钥材料都存储在 `Zeroizing<Vec<u8>>` 容器中，
//! 在丢弃时自动清除敏感数据。
//!
//! ### Flexibility | 灵活性
//! The module provides both typed and untyped key variants:
//! - **Untyped keys**: Flexible storage and conversion
//! - **Typed keys**: Algorithm-bound keys for safe operations
//!
//! 模块提供类型化和非类型化密钥变体：
//! - **非类型化密钥**: 灵活的存储和转换
//! - **类型化密钥**: 用于安全操作的算法绑定密钥
//!
//! ## Usage Examples | 使用示例
//!
//! ### KEM Operations | KEM 操作
//! ```rust
//! use seal_crypto_wrapper::algorithms::asymmetric::AsymmetricAlgorithm;
//!
//! #[cfg(feature = "asymmetric-kem")]
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let algorithm = AsymmetricAlgorithm::build().kem().kyber512();
//!     let kem = algorithm.into_asymmetric_wrapper();
//!     let keypair = kem.generate_keypair()?;
//!
//!     let (public_key, private_key) = keypair.into_keypair();
//!     let (shared_secret, ciphertext) = kem.encapsulate_key(&public_key)?;
//!     let recovered_secret = kem.decapsulate_key(&private_key, &ciphertext)?;
//! }
//! ```
//!
//! ### Digital Signatures | 数字签名
//! ```rust
//! use seal_crypto_wrapper::algorithms::asymmetric::AsymmetricAlgorithm;
//!#[cfg(feature = "asymmetric-signature")]
//! fn main() -> Result< (), Box < dyn std::error::Error > > {
//!     let algorithm = AsymmetricAlgorithm::build().signature().ed25519();
//!     let signer = algorithm.into_wrapper();
//!     let keypair = signer.generate_keypair() ?;
//!     
//!     let (public_key, private_key) = keypair.into_keypair();
//!     let message = b"Hello, World!";
//!     let signature = signer.sign(message, & private_key) ?;
//!     signer.verify(message, & public_key, signature) ?;
//!     Ok::< (), Box < dyn std::error::Error > > (())
//! }
//! ```

use crate::error::Error;
use seal_crypto::prelude::{AsymmetricKeySet, Key};
use seal_crypto::zeroize::{self, Zeroizing};

#[cfg(feature = "asymmetric-kem")]
use {
    crate::algorithms::asymmetric::kem::KemAlgorithm,
    kem::{TypedKemPrivateKey, TypedKemPublicKey},
};

#[cfg(feature = "asymmetric-key-agreement")]
use crate::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;

#[cfg(feature = "asymmetric-signature")]
use crate::algorithms::asymmetric::signature::SignatureAlgorithm;

// Digital signature key types | 数字签名密钥类型
#[cfg(feature = "asymmetric-signature")]
pub mod signature;

// Key encapsulation mechanism key types | 密钥封装机制密钥类型
#[cfg(feature = "asymmetric-kem")]
pub mod kem;

// Key agreement key types | 密钥协商密钥类型
#[cfg(feature = "asymmetric-key-agreement")]
pub mod key_agreement;

/// Macro for dispatching KEM operations across different algorithm implementations.
///
/// 用于在不同算法实现间分发 KEM 操作的宏。
///
/// ## Purpose | 目的
///
/// This macro provides a unified way to handle operations that need to work with
/// different concrete KEM algorithm types (RSA, Kyber) while maintaining type safety.
/// It maps algorithm enum variants to their corresponding concrete types.
///
/// 此宏提供了一种统一的方式来处理需要与不同具体 KEM 算法类型（RSA、Kyber）
/// 一起工作的操作，同时保持类型安全。它将算法枚举变体映射到相应的具体类型。
///
/// ## Supported Algorithms | 支持的算法
///
/// - **RSA-2048/4096**: With SHA-256, SHA-384, or SHA-512 hash functions
/// - **Kyber-512/768/1024**: Post-quantum lattice-based algorithms
///
/// - **RSA-2048/4096**: 使用 SHA-256、SHA-384 或 SHA-512 哈希函数
/// - **Kyber-512/768/1024**: 后量子基于格的算法
#[cfg(feature = "asymmetric-kem")]
#[macro_export(local_inner_macros)]
macro_rules! dispatch_kem {
    ($algorithm:expr, $action:ident) => {{
        use crate::algorithms::asymmetric::kem::{KemAlgorithm, KyberSecurityLevel, RsaBits};
        use crate::algorithms::hash::HashAlgorithm;
        use ::seal_crypto::schemes::asymmetric::post_quantum::kyber::{
            Kyber512, Kyber768, Kyber1024,
        };
        use ::seal_crypto::schemes::asymmetric::traditional::rsa::{Rsa2048, Rsa4096};
        use ::seal_crypto::schemes::hash::{Sha256, Sha384, Sha512};
        match $algorithm {
            KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithm::Sha256) => {
                $action!(
                    Rsa2048<Sha256>,
                    KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithm::Sha256)
                )
            }
            KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithm::Sha384) => {
                $action!(
                    Rsa2048<Sha384>,
                    KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithm::Sha384)
                )
            }
            KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithm::Sha512) => {
                $action!(
                    Rsa2048<Sha512>,
                    KemAlgorithm::Rsa(RsaBits::B2048, HashAlgorithm::Sha512)
                )
            }
            KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithm::Sha256) => {
                $action!(
                    Rsa4096<Sha256>,
                    KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithm::Sha256)
                )
            }
            KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithm::Sha384) => {
                $action!(
                    Rsa4096<Sha384>,
                    KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithm::Sha384)
                )
            }
            KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithm::Sha512) => {
                $action!(
                    Rsa4096<Sha512>,
                    KemAlgorithm::Rsa(RsaBits::B4096, HashAlgorithm::Sha512)
                )
            }
            KemAlgorithm::Kyber(KyberSecurityLevel::L512) => {
                $action!(Kyber512, KemAlgorithm::Kyber(KyberSecurityLevel::L512))
            }
            KemAlgorithm::Kyber(KyberSecurityLevel::L768) => {
                $action!(Kyber768, KemAlgorithm::Kyber(KyberSecurityLevel::L768))
            }
            KemAlgorithm::Kyber(KyberSecurityLevel::L1024) => {
                $action!(Kyber1024, KemAlgorithm::Kyber(KyberSecurityLevel::L1024))
            }
        }
    }};
}

/// Macro for dispatching signature operations across different algorithm implementations.
///
/// 用于在不同算法实现间分发签名操作的宏。
///
/// ## Purpose | 目的
///
/// This macro provides a unified way to handle operations that need to work with
/// different concrete signature algorithm types while maintaining type safety.
/// It supports both traditional and post-quantum signature algorithms.
///
/// 此宏提供了一种统一的方式来处理需要与不同具体签名算法类型一起工作的操作，
/// 同时保持类型安全。它支持传统和后量子签名算法。
///
/// ## Supported Algorithms | 支持的算法
///
/// - **Ed25519**: High-performance Edwards curve signatures
/// - **ECDSA P-256**: NIST standard elliptic curve signatures
/// - **Dilithium-2/3/5**: Post-quantum lattice-based signatures
///
/// - **Ed25519**: 高性能 Edwards 曲线签名
/// - **ECDSA P-256**: NIST 标准椭圆曲线签名
/// - **Dilithium-2/3/5**: 后量子基于格的签名
#[cfg(feature = "asymmetric-signature")]
#[macro_export(local_inner_macros)]
macro_rules! dispatch_signature {
    ($algorithm:expr, $action:ident) => {{
        use crate::algorithms::asymmetric::signature::{
            DilithiumSecurityLevel, SignatureAlgorithm,
        };
        use ::seal_crypto::schemes::asymmetric::traditional::ecc::{EcdsaP256, Ed25519};
        match $algorithm {
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L2) => {
                $action!(
                    ::seal_crypto::schemes::asymmetric::post_quantum::dilithium::Dilithium2,
                    SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L2)
                )
            }
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L3) => {
                $action!(
                    ::seal_crypto::schemes::asymmetric::post_quantum::dilithium::Dilithium3,
                    SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L3)
                )
            }
            SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L5) => {
                $action!(
                    ::seal_crypto::schemes::asymmetric::post_quantum::dilithium::Dilithium5,
                    SignatureAlgorithm::Dilithium(DilithiumSecurityLevel::L5)
                )
            }
            SignatureAlgorithm::Ed25519 => $action!(Ed25519, SignatureAlgorithm::Ed25519),
            SignatureAlgorithm::EcdsaP256 => {
                $action!(EcdsaP256, SignatureAlgorithm::EcdsaP256)
            }
        }
    }};
}

/// Macro for dispatching key agreement operations across different algorithm implementations.
///
/// 用于在不同算法实现间分发密钥协商操作的宏。
///
/// ## Purpose | 目的
///
/// This macro provides a unified way to handle operations that need to work with
/// different concrete key agreement algorithm types while maintaining type safety.
/// Currently supports elliptic curve Diffie-Hellman key agreement.
///
/// 此宏提供了一种统一的方式来处理需要与不同具体密钥协商算法类型一起工作的操作，
/// 同时保持类型安全。目前支持椭圆曲线 Diffie-Hellman 密钥协商。
///
/// ## Supported Algorithms | 支持的算法
///
/// - **ECDH P-256**: Elliptic Curve Diffie-Hellman over NIST P-256 curve
///
/// - **ECDH P-256**: 基于 NIST P-256 曲线的椭圆曲线 Diffie-Hellman
#[cfg(feature = "asymmetric-key-agreement")]
#[macro_export(local_inner_macros)]
macro_rules! dispatch_key_agreement {
    ($algorithm:expr, $action:ident) => {{
        use crate::algorithms::asymmetric::key_agreement::KeyAgreementAlgorithm;
        use ::seal_crypto::schemes::asymmetric::traditional::ecdh::EcdhP256;
        match $algorithm {
            KeyAgreementAlgorithm::EcdhP256 => {
                $action!(EcdhP256, KeyAgreementAlgorithm::EcdhP256)
            }
        }
    }};
}

/// Untyped asymmetric private key for flexible cryptographic operations.
///
/// 用于灵活密码操作的非类型化非对称私钥。
///
/// ## Purpose | 目的
///
/// This type stores raw private key material without algorithm binding, providing
/// flexibility for key management operations such as storage, import/export,
/// and conversion to typed keys when the algorithm is determined.
///
/// 此类型存储没有算法绑定的原始私钥材料，为密钥管理操作提供灵活性，
/// 如存储、导入/导出，以及在确定算法时转换为类型化密钥。
///
/// ## Security Features | 安全特性
///
/// - **Automatic Zeroing**: Memory is cleared when the key is dropped
/// - **Secure Storage**: Uses `Zeroizing<Vec<u8>>` for sensitive data protection
/// - **Serialization Safety**: Supports secure serialization with proper cleanup
///
/// - **自动清零**: 密钥丢弃时清除内存
/// - **安全存储**: 使用 `Zeroizing<Vec<u8>>` 保护敏感数据
/// - **序列化安全**: 支持具有适当清理的安全序列化
///
/// ## Use Cases | 使用场景
///
/// - **Key Import**: Loading keys from external sources or files
/// - **Key Storage**: Flexible storage before algorithm determination
/// - **Key Conversion**: Converting between different key formats
/// - **Multi-Algorithm Support**: Single key type for multiple algorithms
///
/// - **密钥导入**: 从外部源或文件加载密钥
/// - **密钥存储**: 算法确定前的灵活存储
/// - **密钥转换**: 在不同密钥格式间转换
/// - **多算法支持**: 多种算法的单一密钥类型
///
/// ## Examples | 示例
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::asymmetric::AsymmetricAlgorithm;
/// use seal_crypto_wrapper::keys::asymmetric::AsymmetricPrivateKey;
///  #[cfg(feature = "asymmetric-kem")]
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Generate a valid key pair first
///     use seal_crypto_wrapper::prelude::TypedAsymmetricPrivateKeyTrait;
///     let algorithm = AsymmetricAlgorithm::build().kem().kyber512();
///     let kem = algorithm.into_asymmetric_wrapper();
///     let keypair = kem.generate_keypair()?;
///     let (public_key, private_key) = keypair.into_keypair();
///
///     // Extract raw bytes from the generated key
///     let key_bytes = private_key.to_bytes();
///     let untyped_key = AsymmetricPrivateKey::new(key_bytes);
///
///     // Convert back to typed key when algorithm is known
///     let typed_key = untyped_key.into_kem_typed(algorithm.into())?;
///     println!("Successfully converted untyped key to typed key");
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AsymmetricPrivateKey(pub Zeroizing<Vec<u8>>);

impl bincode::Encode for AsymmetricPrivateKey {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        let bytes = self.0.as_slice();
        bincode::Encode::encode(bytes, encoder)?;
        Ok(())
    }
}

impl<Context> bincode::Decode<Context> for AsymmetricPrivateKey {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let bytes = bincode::Decode::decode(decoder)?;
        Ok(Self(Zeroizing::new(bytes)))
    }
}
impl<'de, Context> bincode::BorrowDecode<'de, Context> for AsymmetricPrivateKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let bytes = bincode::BorrowDecode::borrow_decode(decoder)?;
        Ok(Self(Zeroizing::new(bytes)))
    }
}

impl AsymmetricPrivateKey {
    /// Creates a new asymmetric private key from raw bytes.
    ///
    /// 从原始字节创建新的非对称私钥。
    ///
    /// ## Security | 安全性
    ///
    /// The input bytes are automatically wrapped in a `Zeroizing` container
    /// to ensure secure cleanup when the key is dropped.
    ///
    /// 输入字节自动包装在 `Zeroizing` 容器中，
    /// 以确保密钥丢弃时的安全清理。
    ///
    /// ## Arguments | 参数
    ///
    /// * `bytes` - Raw private key material
    ///
    /// * `bytes` - 原始私钥材料
    pub fn new(bytes: impl Into<zeroize::Zeroizing<Vec<u8>>>) -> Self {
        Self(bytes.into())
    }

    /// Returns a reference to the raw key bytes.
    ///
    /// 返回原始密钥字节的引用。
    ///
    /// ## Security Warning | 安全警告
    ///
    /// The returned slice provides access to sensitive private key material.
    /// Avoid copying, logging, or exposing these bytes.
    ///
    /// 返回的切片提供对敏感私钥材料的访问。
    /// 避免复制、记录或暴露这些字节。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns a copy of the raw key bytes.
    ///
    /// 返回原始密钥字节的副本。
    ///
    /// ## Security Warning | 安全警告
    ///
    /// The returned `Vec<u8>` does not have automatic zeroing. Use `into_bytes()`
    /// when possible to maintain better security properties.
    ///
    /// 返回的 `Vec<u8>` 没有自动清零。尽可能使用 `into_bytes()`
    /// 以保持更好的安全属性。
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Consumes the key and returns the raw bytes with secure cleanup.
    ///
    /// 消费密钥并返回具有安全清理的原始字节。
    ///
    /// The returned `Zeroizing<Vec<u8>>` will automatically zero its contents
    /// when dropped, providing secure cleanup of sensitive data.
    ///
    /// 返回的 `Zeroizing<Vec<u8>>` 在丢弃时会自动清零其内容，
    /// 为敏感数据提供安全清理。
    pub fn into_bytes(self) -> zeroize::Zeroizing<Vec<u8>> {
        self.0
    }

    /// Converts the untyped key into a KEM-specific typed private key.
    ///
    /// 将非类型化密钥转换为 KEM 特定的类型化私钥。
    ///
    /// ## Purpose | 目的
    ///
    /// This method binds the raw key material to a specific KEM algorithm,
    /// creating a typed key that can only be used with that algorithm.
    /// This prevents accidental misuse of keys with wrong algorithms.
    ///
    /// 此方法将原始密钥材料绑定到特定的 KEM 算法，
    /// 创建只能与该算法一起使用的类型化密钥。
    /// 这防止了密钥与错误算法的意外误用。
    ///
    /// ## Arguments | 参数
    ///
    /// * `algorithm` - The KEM algorithm to bind this key to
    ///
    /// * `algorithm` - 要将此密钥绑定到的 KEM 算法
    ///
    /// ## Returns | 返回值
    ///
    /// A typed KEM private key that can only be used with the specified algorithm.
    ///
    /// 只能与指定算法一起使用的类型化 KEM 私钥。
    ///
    /// ## Errors | 错误
    ///
    /// Returns an error if the key material is invalid for the specified algorithm.
    ///
    /// 如果密钥材料对指定算法无效，则返回错误。
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::asymmetric::AsymmetricAlgorithm;
    /// use seal_crypto_wrapper::keys::asymmetric::AsymmetricPrivateKey;
    ///
    /// #[cfg(feature = "asymmetric-kem")]
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     // Generate a valid key pair first
    ///     use seal_crypto_wrapper::prelude::TypedAsymmetricPrivateKeyTrait;
    ///     let algorithm = AsymmetricAlgorithm::build().kem().kyber512();
    ///     let kem = algorithm.into_asymmetric_wrapper();
    ///     let keypair = kem.generate_keypair()?;
    ///     let (public_key, private_key) = keypair.into_keypair();
    ///
    ///     // Extract raw bytes from the generated key
    ///     let key_bytes = private_key.to_bytes();
    ///     let untyped_key = AsymmetricPrivateKey::new(key_bytes);
    ///
    ///     // Convert to typed key when algorithm is known
    ///     let typed_key = untyped_key.into_kem_typed(algorithm.into())?;
    ///     println!("Successfully converted to typed KEM key");
    ///     Ok(())
    /// }
    ///
    /// ```
    #[cfg(feature = "asymmetric-kem")]
    pub fn into_kem_typed(self, algorithm: KemAlgorithm) -> Result<TypedKemPrivateKey, Error> {
        macro_rules! into_typed_sk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let sk = <KT as AsymmetricKeySet>::PrivateKey::from_bytes(self.as_bytes())?;
                Ok(TypedKemPrivateKey {
                    key: AsymmetricPrivateKey::new(sk.to_bytes()?),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_kem!(algorithm, into_typed_sk)
    }

    /// Converts the raw key bytes into a typed signature private key.
    ///
    /// 将原始密钥字节转换为类型化的签名私钥。
    #[cfg(feature = "asymmetric-signature")]
    pub fn into_signature_typed(
        self,
        algorithm: SignatureAlgorithm,
    ) -> Result<signature::TypedSignaturePrivateKey, Error> {
        use signature::TypedSignaturePrivateKey;
        macro_rules! into_typed_sk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let sk = <KT as AsymmetricKeySet>::PrivateKey::from_bytes(self.as_bytes())?;
                Ok(TypedSignaturePrivateKey {
                    key: AsymmetricPrivateKey::new(sk.to_bytes()?),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_signature!(algorithm, into_typed_sk)
    }

    /// Converts the raw key bytes into a typed key agreement private key.
    ///
    /// 将原始密钥字节转换为类型化的密钥协商私钥。
    #[cfg(feature = "asymmetric-key-agreement")]
    pub fn into_key_agreement_typed(
        self,
        algorithm: KeyAgreementAlgorithm,
    ) -> Result<key_agreement::TypedKeyAgreementPrivateKey, Error> {
        use key_agreement::TypedKeyAgreementPrivateKey;
        macro_rules! into_typed_sk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let sk = <KT as AsymmetricKeySet>::PrivateKey::from_bytes(self.as_bytes())?;
                Ok(TypedKeyAgreementPrivateKey {
                    key: AsymmetricPrivateKey::new(sk.to_bytes()?),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_key_agreement!(algorithm, into_typed_sk)
    }
}

/// A byte wrapper for an asymmetric public key.
///
/// 非对称公钥的字节包装器。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AsymmetricPublicKey(pub zeroize::Zeroizing<Vec<u8>>);

impl bincode::Encode for AsymmetricPublicKey {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> core::result::Result<(), bincode::error::EncodeError> {
        let bytes = self.0.as_slice();
        bincode::Encode::encode(bytes, encoder)?;
        Ok(())
    }
}

impl<Context> bincode::Decode<Context> for AsymmetricPublicKey {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> core::result::Result<Self, bincode::error::DecodeError> {
        let bytes = bincode::Decode::decode(decoder)?;
        Ok(Self(Zeroizing::new(bytes)))
    }
}
impl<'de, Context> bincode::BorrowDecode<'de, Context> for AsymmetricPublicKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = Context>>(
        decoder: &mut D,
    ) -> core::result::Result<Self, bincode::error::DecodeError> {
        let bytes = bincode::BorrowDecode::borrow_decode(decoder)?;
        Ok(Self(Zeroizing::new(bytes)))
    }
}

impl AsymmetricPublicKey {
    /// Create a new asymmetric public key from bytes
    ///
    /// 从字节创建一个新的非对称公钥
    pub fn new(bytes: impl Into<zeroize::Zeroizing<Vec<u8>>>) -> Self {
        Self(bytes.into())
    }

    /// Get a reference to the raw bytes of the key
    ///
    /// 获取密钥原始字节的引用
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Consume the key and return the inner bytes
    ///
    /// 消耗密钥并返回内部字节
    pub fn into_bytes(self) -> zeroize::Zeroizing<Vec<u8>> {
        self.0
    }

    #[cfg(feature = "asymmetric-kem")]
    pub fn into_kem_typed(self, algorithm: KemAlgorithm) -> Result<TypedKemPublicKey, Error> {
        macro_rules! into_typed_pk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let pk = <KT as AsymmetricKeySet>::PublicKey::from_bytes(self.as_bytes())?;
                Ok(TypedKemPublicKey {
                    key: AsymmetricPublicKey::new(pk.to_bytes()?),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_kem!(algorithm, into_typed_pk)
    }

    /// Converts the raw key bytes into a typed signature public key.
    ///
    /// 将原始密钥字节转换为类型化的签名公钥。
    #[cfg(feature = "asymmetric-signature")]
    pub fn into_signature_typed(
        self,
        algorithm: SignatureAlgorithm,
    ) -> Result<signature::TypedSignaturePublicKey, Error> {
        use signature::TypedSignaturePublicKey;
        macro_rules! into_typed_pk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let pk = <KT as AsymmetricKeySet>::PublicKey::from_bytes(self.as_bytes())?;
                Ok(TypedSignaturePublicKey {
                    key: AsymmetricPublicKey::new(pk.to_bytes()?),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_signature!(algorithm, into_typed_pk)
    }

    /// Converts the raw key bytes into a typed key agreement public key.
    ///
    /// 将原始密钥字节转换为类型化的密钥协商公钥。
    #[cfg(feature = "asymmetric-key-agreement")]
    pub fn into_key_agreement_typed(
        self,
        algorithm: KeyAgreementAlgorithm,
    ) -> Result<key_agreement::TypedKeyAgreementPublicKey, Error> {
        use key_agreement::TypedKeyAgreementPublicKey;
        macro_rules! into_typed_pk {
            ($key_type:ty, $alg_enum:expr) => {{
                type KT = $key_type;
                let pk = <KT as AsymmetricKeySet>::PublicKey::from_bytes(self.as_bytes())?;
                Ok(TypedKeyAgreementPublicKey {
                    key: AsymmetricPublicKey::new(pk.to_bytes()?),
                    algorithm: $alg_enum,
                })
            }};
        }
        dispatch_key_agreement!(algorithm, into_typed_pk)
    }
}

/// A trait for typed asymmetric keys.
///
/// 类型化非对称密钥的 trait。
pub trait TypedAsymmetricKeyTrait: AsRef<[u8]> {
    /// The algorithm enum.
    ///
    /// 算法枚举。
    type Algorithm: Copy;

    /// Returns the algorithm of the key.
    ///
    /// 返回密钥的算法。
    fn algorithm(&self) -> Self::Algorithm;
}

pub trait TypedAsymmetricPublicKeyTrait: TypedAsymmetricKeyTrait {
    fn to_bytes(&self) -> Vec<u8>;
    fn untyped(&self) -> AsymmetricPublicKey;
    fn as_bytes(&self) -> &[u8];
    fn into_bytes(self) -> ::seal_crypto::zeroize::Zeroizing<Vec<u8>>;
}

pub trait TypedAsymmetricPrivateKeyTrait: TypedAsymmetricKeyTrait {
    fn to_bytes(&self) -> Vec<u8>;
    fn untyped(&self) -> AsymmetricPrivateKey;
    fn as_bytes(&self) -> &[u8];
    fn into_bytes(self) -> ::seal_crypto::zeroize::Zeroizing<Vec<u8>>;
}

#[macro_export(local_inner_macros)]
macro_rules! impl_typed_asymmetric_private_key {
    ($typed_key:ident, $alg_type:ty) => {
        impl $crate::keys::asymmetric::TypedAsymmetricPrivateKeyTrait for $typed_key {
            fn to_bytes(&self) -> Vec<u8> {
                self.key.to_bytes()
            }

            fn untyped(&self) -> AsymmetricPrivateKey {
                self.key.clone()
            }

            fn as_bytes(&self) -> &[u8] {
                self.key.as_bytes()
            }

            fn into_bytes(self) -> ::seal_crypto::zeroize::Zeroizing<Vec<u8>> {
                self.key.into_bytes()
            }
        }

        impl AsRef<[u8]> for $typed_key {
            fn as_ref(&self) -> &[u8] {
                self.key.as_bytes()
            }
        }

        impl $crate::keys::asymmetric::TypedAsymmetricKeyTrait for $typed_key {
            type Algorithm = $alg_type;

            fn algorithm(&self) -> Self::Algorithm {
                self.algorithm
            }
        }
    };
}

#[macro_export(local_inner_macros)]
macro_rules! impl_typed_asymmetric_public_key {
    ($typed_key:ident, $alg_type:ty) => {
        impl $crate::keys::asymmetric::TypedAsymmetricPublicKeyTrait for $typed_key {
            fn to_bytes(&self) -> Vec<u8> {
                self.key.to_bytes()
            }

            fn untyped(&self) -> AsymmetricPublicKey {
                self.key.clone()
            }

            fn as_bytes(&self) -> &[u8] {
                self.key.as_bytes()
            }

            fn into_bytes(self) -> ::seal_crypto::zeroize::Zeroizing<Vec<u8>> {
                self.key.into_bytes()
            }
        }

        impl AsRef<[u8]> for $typed_key {
            fn as_ref(&self) -> &[u8] {
                self.key.as_bytes()
            }
        }

        impl $crate::keys::asymmetric::TypedAsymmetricKeyTrait for $typed_key {
            type Algorithm = $alg_type;

            fn algorithm(&self) -> Self::Algorithm {
                self.algorithm
            }
        }
    };
}
