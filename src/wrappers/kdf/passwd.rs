//! Password-based Key Derivation Function (KDF) algorithm wrappers for low-entropy inputs.
//!
//! 用于低熵输入的基于密码的密钥派生函数 (KDF) 算法包装器。
//!
//! ## Overview | 概述
//!
//! This module provides concrete implementations of password-based KDF algorithms
//! that are specifically designed to work with low-entropy inputs such as user
//! passwords, PINs, or passphrases. These algorithms use computational cost to
//! make brute-force attacks impractical.
//!
//! 此模块提供基于密码的 KDF 算法的具体实现，
//! 专门设计用于处理低熵输入，如用户密码、PIN 或密码短语。
//! 这些算法使用计算成本使暴力攻击变得不切实际。
//!
//! ## Supported Algorithms | 支持的算法
//!
//! ### Argon2 (Recommended)
//! - **Type**: Memory-hard function
//! - **Resistance**: GPU, FPGA, and ASIC attacks
//! - **Parameters**: Memory cost, time cost, parallelism
//! - **Security**: Excellent against specialized hardware
//!
//! ### PBKDF2 (Legacy Support)
//! - **PBKDF2-SHA256**: Widely supported, moderate security
//! - **PBKDF2-SHA384**: Higher security margin
//! - **PBKDF2-SHA512**: Maximum security for PBKDF2
//! - **Limitation**: Vulnerable to GPU/ASIC attacks
//!
//! ## Security Comparison | 安全性对比
//!
//! | Algorithm | Memory Usage | GPU Resistance | ASIC Resistance | Performance |
//! |-----------|--------------|----------------|-----------------|-------------|
//! | Argon2    | High         | Excellent      | Excellent       | Medium      |
//! | PBKDF2    | Low          | Poor           | Poor            | High        |
//!
//! ## Usage Guidelines | 使用指南
//!
//! - **New Applications**: Use Argon2 for better security
//! - **Legacy Systems**: Use PBKDF2 when required for compatibility
//! - **High Security**: Use Argon2 with high memory cost
//! - **Resource Constrained**: Use PBKDF2 with high iteration count
//!
//! - **新应用**: 使用 Argon2 获得更好的安全性
//! - **遗留系统**: 需要兼容性时使用 PBKDF2
//! - **高安全性**: 使用高内存成本的 Argon2
//! - **资源受限**: 使用高迭代次数的 PBKDF2

use crate::algorithms::HashAlgorithmEnum;
use crate::algorithms::kdf::passwd::{Argon2Params, KdfPasswordAlgorithm};
use crate::error::{Error, Result};
use crate::traits::KdfPasswordAlgorithmTrait;
use seal_crypto::prelude::PasswordBasedDerivation;
use seal_crypto::schemes::kdf::{
    argon2::Argon2,
    pbkdf2::{Pbkdf2Sha256, Pbkdf2Sha384, Pbkdf2Sha512},
};
use seal_crypto::secrecy::SecretBox;
use seal_crypto::zeroize::Zeroizing;
use std::ops::Deref;

/// Argon2 password hashing algorithm wrapper with memory-hard security.
///
/// 具有内存困难安全性的 Argon2 密码哈希算法包装器。
///
/// ## Algorithm Properties | 算法属性
///
/// - **Type**: Memory-hard function
/// - **Standard**: RFC 9106
/// - **Security**: Resistant to GPU, FPGA, and ASIC attacks
/// - **Parameters**: Configurable memory, time, and parallelism costs
///
/// ## Security Advantages | 安全优势
///
/// Argon2 is specifically designed to resist attacks using specialized hardware:
/// - **Memory-hard**: Requires significant RAM, making GPU attacks expensive
/// - **Time-memory trade-offs**: Resistant to optimization attacks
/// - **Side-channel resistance**: Designed to minimize timing attacks
///
/// Argon2 专门设计用于抵抗使用专用硬件的攻击：
/// - **内存困难**: 需要大量 RAM，使 GPU 攻击成本高昂
/// - **时间-内存权衡**: 抗优化攻击
/// - **侧信道抗性**: 设计用于最小化时序攻击
///
/// ## Parameter Guidelines | 参数指南
///
/// | Use Case | Memory (KB) | Time | Parallelism | Security Level |
/// |----------|-------------|------|-------------|----------------|
/// | Interactive | 65536 | 2 | 1 | Medium |
/// | Server | 262144 | 3 | 4 | High |
/// | High Security | 1048576 | 4 | 8 | Very High |
///
/// ## Examples | 示例
///
/// ```rust
/// use seal_crypto_wrapper::wrappers::kdf::passwd::Argon2Wrapper;
/// use seal_crypto::secrecy::SecretBox;
/// use seal_crypto_wrapper::prelude::KdfPasswordAlgorithmTrait;
///
/// // Default parameters (recommended for most uses)
/// let argon2 = Argon2Wrapper::default();
///
/// // Custom parameters for high security
/// let high_sec_argon2 = Argon2Wrapper::new(1048576, 4, 8);
///
/// let password = SecretBox::new(b"user_password".to_vec().into_boxed_slice());
/// let salt = b"random_salt_16_bytes";
/// let derived_key = argon2.derive(&password, salt, 32)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Argon2Wrapper {
    algorithm: Argon2,
    is_default: bool,
}

impl Argon2Wrapper {
    /// Creates a new Argon2 wrapper with custom parameters.
    ///
    /// 使用自定义参数创建新的 Argon2 包装器。
    ///
    /// ## Parameters | 参数
    ///
    /// * `m_cost` - Memory cost in KB (minimum 8)
    /// * `t_cost` - Time cost (iterations, minimum 1)
    /// * `p_cost` - Parallelism (threads, minimum 1)
    ///
    /// * `m_cost` - 内存成本（KB）（最小值 8）
    /// * `t_cost` - 时间成本（迭代次数，最小值 1）
    /// * `p_cost` - 并行度（线程数，最小值 1）
    ///
    /// ## Security vs Performance | 安全性与性能
    ///
    /// Higher values provide better security but require more resources:
    /// - Increase `m_cost` to resist memory-optimized attacks
    /// - Increase `t_cost` to resist time-optimized attacks
    /// - Increase `p_cost` to utilize multiple CPU cores
    ///
    /// 更高的值提供更好的安全性但需要更多资源：
    /// - 增加 `m_cost` 以抵抗内存优化攻击
    /// - 增加 `t_cost` 以抵抗时间优化攻击
    /// - 增加 `p_cost` 以利用多个 CPU 核心
    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
        Self {
            algorithm: Argon2::new(m_cost, t_cost, p_cost),
            is_default: false,
        }
    }
}

impl Default for Argon2Wrapper {
    /// Creates an Argon2 wrapper with secure default parameters.
    ///
    /// 使用安全默认参数创建 Argon2 包装器。
    ///
    /// ## Default Parameters | 默认参数
    ///
    /// The default configuration provides a good balance of security and performance
    /// for most server applications:
    /// - **Memory Cost**: 65536 KB (64 MB)
    /// - **Time Cost**: 3 iterations
    /// - **Parallelism**: 4 threads
    ///
    /// 默认配置为大多数服务器应用提供了安全性和性能的良好平衡：
    /// - **内存成本**: 65536 KB (64 MB)
    /// - **时间成本**: 3 次迭代
    /// - **并行度**: 4 个线程
    fn default() -> Self {
        Self {
            algorithm: Argon2::default(),
            is_default: true,
        }
    }
}

impl KdfPasswordAlgorithmTrait for Argon2Wrapper {
    /// Derives key material from a password using Argon2.
    ///
    /// 使用 Argon2 从密码派生密钥材料。
    ///
    /// ## Parameters | 参数
    ///
    /// * `password` - The password in a secure container
    /// * `salt` - Random salt for key separation (minimum 16 bytes recommended)
    /// * `output_len` - Desired length of derived key material
    ///
    /// * `password` - 安全容器中的密码
    /// * `salt` - 用于密钥分离的随机盐（推荐最少 16 字节）
    /// * `output_len` - 派生密钥材料的所需长度
    ///
    /// ## Returns | 返回值
    ///
    /// Derived key material in a `Zeroizing<Vec<u8>>` that automatically
    /// clears memory when dropped.
    ///
    /// `Zeroizing<Vec<u8>>` 中的派生密钥材料，在丢弃时自动清除内存。
    ///
    /// ## Security Notes | 安全注意事项
    ///
    /// - Use a unique, random salt for each password
    /// - Store the salt alongside the derived key for verification
    /// - Consider the computational cost when choosing parameters
    ///
    /// - 为每个密码使用唯一的随机盐
    /// - 将盐与派生密钥一起存储以进行验证
    /// - 选择参数时考虑计算成本
    fn derive(
        &self,
        password: &SecretBox<[u8]>,
        salt: &[u8],
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.algorithm
            .derive(password, salt, output_len)
            .map(|dk| dk.0)
            .map_err(Error::from)
    }

    /// Returns the algorithm identifier for this wrapper.
    ///
    /// 返回此包装器的算法标识符。
    fn algorithm(&self) -> KdfPasswordAlgorithm {
        if self.is_default {
            KdfPasswordAlgorithm::Argon2(None)
        } else {
            KdfPasswordAlgorithm::Argon2(Some(Argon2Params {
                m_cost: self.algorithm.m_cost,
                t_cost: self.algorithm.t_cost,
                p_cost: self.algorithm.p_cost,
            }))
        }
    }

    /// Creates a boxed clone of this wrapper.
    ///
    /// 创建此包装器的 boxed 克隆。
    fn clone_box(&self) -> Box<dyn KdfPasswordAlgorithmTrait> {
        Box::new(self.clone())
    }

    fn into_boxed(self) -> Box<dyn KdfPasswordAlgorithmTrait> {
        Box::new(self)
    }
}

macro_rules! impl_kdf_pbkdf_algorithm {
    ($wrapper:ident, $algo:ty, $hash_enum:expr, $kind:path) => {
        #[derive(Clone, Debug)]
        pub struct $wrapper {
            algorithm: $algo,
            is_default: bool,
        }

        impl $wrapper {
            pub fn new(c: u32) -> Self {
                Self {
                    algorithm: <$algo>::new(c),
                    is_default: false,
                }
            }
        }

        impl Default for $wrapper {
            fn default() -> Self {
                Self {
                    algorithm: <$algo>::default(),
                    is_default: true,
                }
            }
        }

        impl KdfPasswordAlgorithmTrait for $wrapper {
            fn derive(
                &self,
                password: &SecretBox<[u8]>,
                salt: &[u8],
                output_len: usize,
            ) -> Result<Zeroizing<Vec<u8>>> {
                self.algorithm
                    .derive(password, salt, output_len)
                    .map(|dk| dk.0)
                    .map_err(Error::from)
            }

            fn algorithm(&self) -> KdfPasswordAlgorithm {
                KdfPasswordAlgorithm::Pbkdf2 {
                    hash: $hash_enum,
                    c: if self.is_default {
                        None
                    } else {
                        Some(self.algorithm.iterations)
                    },
                }
            }

            fn clone_box(&self) -> Box<dyn KdfPasswordAlgorithmTrait> {
                Box::new(self.clone())
            }

            fn into_boxed(self) -> Box<dyn KdfPasswordAlgorithmTrait> {
                Box::new(self)
            }
        }
    };
}

impl_kdf_pbkdf_algorithm!(
    Pbkdf2Sha256Wrapper,
    Pbkdf2Sha256,
    HashAlgorithmEnum::Sha256,
    KdfPasswordAlgorithmKind::Pbkdf2Sha256
);
impl_kdf_pbkdf_algorithm!(
    Pbkdf2Sha384Wrapper,
    Pbkdf2Sha384,
    HashAlgorithmEnum::Sha384,
    KdfPasswordAlgorithmKind::Pbkdf2Sha384
);
impl_kdf_pbkdf_algorithm!(
    Pbkdf2Sha512Wrapper,
    Pbkdf2Sha512,
    HashAlgorithmEnum::Sha512,
    KdfPasswordAlgorithmKind::Pbkdf2Sha512
);

/// Universal wrapper for password-based KDF algorithms providing runtime algorithm selection.
///
/// 提供运行时算法选择的基于密码的 KDF 算法通用包装器。
///
/// ## Purpose | 目的
///
/// This wrapper provides a unified interface for all password-based KDF algorithms,
/// allowing runtime algorithm selection while maintaining type safety. It acts
/// as a bridge between algorithm enums and concrete implementations.
///
/// 此包装器为所有基于密码的 KDF 算法提供统一接口，
/// 允许运行时算法选择同时保持类型安全。它充当算法枚举和具体实现之间的桥梁。
///
/// ## Features | 特性
///
/// - **Runtime Polymorphism**: Switch between algorithms at runtime
/// - **Unified Interface**: Same API for all password-based KDF algorithms
/// - **Memory Safety**: Automatic zeroing of derived key material
/// - **Attack Resistance**: Configurable computational cost parameters
///
/// - **运行时多态性**: 在运行时切换算法
/// - **统一接口**: 所有基于密码的 KDF 算法的相同 API
/// - **内存安全**: 派生密钥材料的自动清零
/// - **攻击抗性**: 可配置的计算成本参数
///
/// ## Examples | 示例
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::kdf::passwd::KdfPasswordAlgorithm;
/// use seal_crypto_wrapper::wrappers::kdf::passwd::KdfPasswordWrapper;
/// use seal_crypto::secrecy::SecretBox;
///
/// // Create from algorithm enum (Argon2 recommended)
/// let algorithm = KdfPasswordAlgorithm::build().argon2_default();
/// let wrapper = algorithm.into_wrapper();
///
/// // Derive key from password
/// let password = SecretBox::new(b"user_password".to_vec().into_boxed_slice());
/// let salt = b"random_salt_16_bytes";
/// let derived_key = wrapper.derive(&password, salt, 32)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct KdfPasswordWrapper {
    algorithm: Box<dyn KdfPasswordAlgorithmTrait>,
}

impl KdfPasswordWrapper {
    pub fn new(algorithm: Box<dyn KdfPasswordAlgorithmTrait>) -> Self {
        Self { algorithm }
    }
}

impl Deref for KdfPasswordWrapper {
    type Target = Box<dyn KdfPasswordAlgorithmTrait>;

    fn deref(&self) -> &Self::Target {
        &self.algorithm
    }
}

impl KdfPasswordAlgorithmTrait for KdfPasswordWrapper {
    fn derive(
        &self,
        password: &SecretBox<[u8]>,
        salt: &[u8],
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.algorithm.derive(password, salt, output_len)
    }

    fn algorithm(&self) -> KdfPasswordAlgorithm {
        self.algorithm.algorithm()
    }

    fn clone_box(&self) -> Box<dyn KdfPasswordAlgorithmTrait> {
        self.algorithm.clone_box()
    }

    fn into_boxed(self) -> Box<dyn KdfPasswordAlgorithmTrait> {
        Box::new(self)
    }
}

impl From<KdfPasswordAlgorithm> for KdfPasswordWrapper {
    fn from(algorithm: KdfPasswordAlgorithm) -> Self {
        algorithm.into_wrapper()
    }
}

impl From<Box<dyn KdfPasswordAlgorithmTrait>> for KdfPasswordWrapper {
    fn from(algorithm: Box<dyn KdfPasswordAlgorithmTrait>) -> Self {
        Self::new(algorithm)
    }
}
