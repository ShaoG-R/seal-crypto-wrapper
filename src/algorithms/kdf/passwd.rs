//! Password-based Key Derivation Functions (KDF) for low-entropy inputs.
//!
//! 用于低熵输入的基于密码的密钥派生函数 (KDF)。
//!
//! ## Overview | 概述
//!
//! Password-based KDFs are specifically designed to work with low-entropy inputs
//! such as user passwords, PINs, or passphrases. They use computational cost
//! (time, memory, or both) to make brute-force attacks impractical, even when
//! the input has limited entropy.
//!
//! 基于密码的 KDF 专门设计用于处理低熵输入，
//! 如用户密码、PIN 或密码短语。它们使用计算成本（时间、内存或两者）
//! 使暴力攻击变得不切实际，即使输入的熵有限。
//!
//! ## Supported Algorithms | 支持的算法
//!
//! ### PBKDF2 (Password-Based Key Derivation Function 2)
//! - **Standard**: RFC 2898, PKCS #5
//! - **Type**: Time-hard function
//! - **Resistance**: CPU-based attacks
//! - **Tunable Parameter**: Iteration count
//!
//! ### Argon2 (Winner of Password Hashing Competition)
//! - **Standard**: RFC 9106
//! - **Type**: Memory-hard function
//! - **Resistance**: GPU, FPGA, and ASIC attacks
//! - **Tunable Parameters**: Memory cost, time cost, parallelism
//!
//! ## Security Comparison | 安全性对比
//!
//! | Algorithm | Type | Memory Usage | GPU Resistance | ASIC Resistance |
//! |-----------|------|--------------|----------------|-----------------|
//! | PBKDF2    | Time-hard | Low | Poor | Poor |
//! | Argon2    | Memory-hard | High | Excellent | Excellent |
//!
//! ## Attack Resistance | 攻击抗性
//!
//! ### PBKDF2 Limitations | PBKDF2 局限性
//! - Vulnerable to GPU-based attacks
//! - Vulnerable to FPGA/ASIC attacks
//! - Only time-based cost function
//!
//! - 易受基于 GPU 的攻击
//! - 易受 FPGA/ASIC 攻击
//! - 仅基于时间的成本函数
//!
//! ### Argon2 Advantages | Argon2 优势
//! - Memory-hard: requires significant RAM
//! - Resistant to specialized hardware
//! - Configurable time/memory trade-offs
//!
//! - 内存困难：需要大量 RAM
//! - 抗专用硬件
//! - 可配置的时间/内存权衡
//!
//! ## Usage Guidelines | 使用指南
//!
//! - **New Applications**: Use Argon2 for better security
//! - **Legacy Compatibility**: Use PBKDF2 when required
//! - **High Security**: Use Argon2 with high memory cost
//! - **Resource Constrained**: Use PBKDF2 with high iteration count
//!
//! - **新应用**: 使用 Argon2 获得更好的安全性
//! - **遗留兼容性**: 需要时使用 PBKDF2
//! - **高安全性**: 使用高内存成本的 Argon2
//! - **资源受限**: 使用高迭代次数的 PBKDF2

use crate::algorithms::HashAlgorithmEnum;
use bincode::{Decode, Encode};

/// Argon2 algorithm parameters for customizing security vs performance trade-offs.
///
/// 用于自定义安全性与性能权衡的 Argon2 算法参数。
///
/// ## Parameters | 参数
///
/// These parameters control the computational cost of Argon2:
///
/// 这些参数控制 Argon2 的计算成本：
///
/// - **Memory Cost (m_cost)**: Amount of memory used in KB
/// - **Time Cost (t_cost)**: Number of iterations
/// - **Parallelism (p_cost)**: Number of parallel threads
///
/// - **内存成本 (m_cost)**: 使用的内存量（KB）
/// - **时间成本 (t_cost)**: 迭代次数
/// - **并行度 (p_cost)**: 并行线程数
///
/// ## Recommended Values | 推荐值
///
/// | Use Case | m_cost | t_cost | p_cost | Security Level |
/// |----------|--------|--------|--------|----------------|
/// | Interactive | 65536 | 2 | 1 | Medium |
/// | Server | 262144 | 3 | 4 | High |
/// | Sensitive | 1048576 | 4 | 8 | Very High |
///
/// ## Security vs Performance | 安全性与性能
///
/// Higher values provide better security but require more resources:
/// - Increase m_cost to resist memory-optimized attacks
/// - Increase t_cost to resist time-optimized attacks
/// - Increase p_cost to utilize multiple CPU cores
///
/// 更高的值提供更好的安全性但需要更多资源：
/// - 增加 m_cost 以抵抗内存优化攻击
/// - 增加 t_cost 以抵抗时间优化攻击
/// - 增加 p_cost 以利用多个 CPU 核心
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, serde::Serialize, serde::Deserialize,
)]
pub struct Argon2Params {
    /// Memory cost in KB (minimum 8).
    ///
    /// 内存成本（KB）（最小值 8）。
    pub m_cost: u32,

    /// Time cost (number of iterations, minimum 1).
    ///
    /// 时间成本（迭代次数，最小值 1）。
    pub t_cost: u32,

    /// Parallelism (number of threads, minimum 1).
    ///
    /// 并行度（线程数，最小值 1）。
    pub p_cost: u32,
}

/// Password-based Key Derivation Function algorithm enumeration.
///
/// 基于密码的密钥派生函数算法枚举。
///
/// ## Algorithm Selection | 算法选择
///
/// Choose based on your security and compatibility requirements:
///
/// 根据您的安全性和兼容性要求选择：
///
/// - **Argon2**: Recommended for new applications (better security)
/// - **PBKDF2**: Use for legacy compatibility or resource constraints
///
/// - **Argon2**: 推荐用于新应用（更好的安全性）
/// - **PBKDF2**: 用于遗留兼容性或资源约束
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, serde::Serialize, serde::Deserialize,
)]
pub enum KdfPasswordAlgorithm {
    /// Argon2 memory-hard password hashing function.
    ///
    /// Argon2 内存困难密码哈希函数。
    ///
    /// ## Properties | 属性
    /// - **Type**: Memory-hard function
    /// - **Standard**: RFC 9106
    /// - **Resistance**: GPU, FPGA, ASIC attacks
    /// - **Parameters**: Memory, time, parallelism costs
    ///
    /// ## Variants | 变体
    /// - `Some(params)`: Custom parameters for specific requirements
    /// - `None`: Default parameters suitable for most applications
    ///
    /// - `Some(params)`: 特定要求的自定义参数
    /// - `None`: 适用于大多数应用的默认参数
    Argon2(Option<Argon2Params>),

    /// PBKDF2 time-hard password-based key derivation function.
    ///
    /// PBKDF2 时间困难的基于密码的密钥派生函数。
    ///
    /// ## Properties | 属性
    /// - **Type**: Time-hard function
    /// - **Standard**: RFC 2898, PKCS #5
    /// - **Resistance**: Basic brute-force attacks
    /// - **Parameters**: Hash function, iteration count
    ///
    /// ## Configuration | 配置
    /// - `hash`: Underlying hash function (SHA-256/384/512)
    /// - `c`: Iteration count (`Some(count)` for custom, `None` for default)
    ///
    /// - `hash`: 底层哈希函数（SHA-256/384/512）
    /// - `c`: 迭代次数（`Some(count)` 自定义，`None` 默认）
    Pbkdf2 {
        hash: HashAlgorithmEnum,
        c: Option<u32>,
    },
}

impl KdfPasswordAlgorithm {
    /// Creates a new password-based KDF algorithm builder.
    ///
    /// 创建新的基于密码的 KDF 算法构建器。
    ///
    /// ## Returns | 返回值
    ///
    /// A builder that provides access to different password-based KDF algorithms.
    /// Use the builder methods to select the specific algorithm and parameters.
    ///
    /// 提供访问不同基于密码的 KDF 算法的构建器。
    /// 使用构建器方法选择特定的算法和参数。
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::kdf::passwd::KdfPasswordAlgorithm;
    ///
    /// // Default configurations
    /// let argon2 = KdfPasswordAlgorithm::build().argon2_default();
    /// let pbkdf2 = KdfPasswordAlgorithm::build().pbkdf2_sha256_default();
    ///
    /// // Custom configurations
    /// let custom_argon2 = KdfPasswordAlgorithm::build().argon2_with_params(65536, 3, 4);
    /// let custom_pbkdf2 = KdfPasswordAlgorithm::build().pbkdf2_sha256_with_params(100000);
    /// ```
    pub fn build() -> KdfPasswordAlgorithmBuilder {
        KdfPasswordAlgorithmBuilder
    }
}

/// Builder for constructing password-based KDF algorithm instances.
///
/// 用于构建基于密码的 KDF 算法实例的构建器。
///
/// ## Usage Pattern | 使用模式
///
/// The builder provides both default and custom parameter methods:
/// - Default methods use secure, recommended parameters
/// - Custom parameter methods allow fine-tuning for specific requirements
///
/// 构建器提供默认和自定义参数方法：
/// - 默认方法使用安全、推荐的参数
/// - 自定义参数方法允许针对特定要求进行微调
///
/// ## Security Guidelines | 安全指南
///
/// - **For new applications**: Use Argon2 for better security
/// - **For compatibility**: Use PBKDF2 when required by standards
/// - **Parameter tuning**: Test performance vs security trade-offs
/// - **Regular updates**: Review and update parameters as hardware improves
///
/// - **新应用**: 使用 Argon2 获得更好的安全性
/// - **兼容性**: 标准要求时使用 PBKDF2
/// - **参数调优**: 测试性能与安全性的权衡
/// - **定期更新**: 随着硬件改进审查和更新参数
pub struct KdfPasswordAlgorithmBuilder;

impl KdfPasswordAlgorithmBuilder {
    /// Selects Argon2 with default parameters.
    ///
    /// 选择使用默认参数的 Argon2。
    ///
    /// ## Default Parameters | 默认参数
    /// - **Memory Cost**: 65536 KB (64 MB)
    /// - **Time Cost**: 3 iterations
    /// - **Parallelism**: 4 threads
    ///
    /// These defaults provide a good balance of security and performance
    /// for most server applications.
    ///
    /// 这些默认值为大多数服务器应用提供了安全性和性能的良好平衡。
    ///
    /// ## Use Cases | 使用场景
    /// - General-purpose password hashing
    /// - User authentication systems
    /// - Password-based encryption
    ///
    /// - 通用密码哈希
    /// - 用户认证系统
    /// - 基于密码的加密
    pub fn argon2_default(self) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Argon2(None)
    }

    /// Selects PBKDF2-SHA256 with default iteration count.
    ///
    /// 选择使用默认迭代次数的 PBKDF2-SHA256。
    ///
    /// ## Default Parameters | 默认参数
    /// - **Hash Function**: SHA-256
    /// - **Iterations**: 100,000 (recommended minimum)
    ///
    /// ## Use Cases | 使用场景
    /// - Legacy system compatibility
    /// - Standards compliance (PKCS #5)
    /// - Resource-constrained environments
    ///
    /// - 遗留系统兼容性
    /// - 标准合规性（PKCS #5）
    /// - 资源受限环境
    pub fn pbkdf2_sha256_default(self) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2 {
            hash: HashAlgorithmEnum::Sha256,
            c: None,
        }
    }

    /// Selects PBKDF2-SHA384 with default iteration count.
    ///
    /// 选择使用默认迭代次数的 PBKDF2-SHA384。
    ///
    /// ## Properties | 属性
    /// - **Hash Function**: SHA-384
    /// - **Security Level**: 192-bit
    /// - **Iterations**: Default secure count
    ///
    /// ## Use Cases | 使用场景
    /// Applications requiring higher security than SHA-256.
    /// 需要比 SHA-256 更高安全性的应用。
    pub fn pbkdf2_sha384_default(self) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2 {
            hash: HashAlgorithmEnum::Sha384,
            c: None,
        }
    }

    /// Selects PBKDF2-SHA512 with default iteration count.
    ///
    /// 选择使用默认迭代次数的 PBKDF2-SHA512。
    ///
    /// ## Properties | 属性
    /// - **Hash Function**: SHA-512
    /// - **Security Level**: 256-bit
    /// - **Iterations**: Default secure count
    ///
    /// ## Use Cases | 使用场景
    /// Maximum security applications using PBKDF2.
    /// 使用 PBKDF2 的最大安全性应用。
    pub fn pbkdf2_sha512_default(self) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2 {
            hash: HashAlgorithmEnum::Sha512,
            c: None,
        }
    }

    /// Selects Argon2 with custom parameters.
    ///
    /// 选择使用自定义参数的 Argon2。
    ///
    /// ## Parameters | 参数
    ///
    /// * `m_cost` - Memory cost in KB (minimum 8)
    /// * `t_cost` - Time cost (iterations, minimum 1)
    /// * `p_cost` - Parallelism (threads, minimum 1)
    ///
    /// ## Parameter Guidelines | 参数指南
    ///
    /// | Security Level | m_cost | t_cost | p_cost |
    /// |----------------|--------|--------|--------|
    /// | Interactive    | 65536  | 2      | 1      |
    /// | Server         | 262144 | 3      | 4      |
    /// | High Security  | 1048576| 4      | 8      |
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::kdf::passwd::KdfPasswordAlgorithm;
    ///
    /// // High security configuration
    /// let high_sec = KdfPasswordAlgorithm::build()
    ///     .argon2_with_params(1048576, 4, 8);
    ///
    /// // Interactive use (faster)
    /// let interactive = KdfPasswordAlgorithm::build()
    ///     .argon2_with_params(65536, 2, 1);
    /// ```
    pub fn argon2_with_params(self, m_cost: u32, t_cost: u32, p_cost: u32) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Argon2(Some(Argon2Params {
            m_cost,
            t_cost,
            p_cost,
        }))
    }

    /// Selects PBKDF2-SHA256 with custom iteration count.
    ///
    /// 选择使用自定义迭代次数的 PBKDF2-SHA256。
    ///
    /// ## Parameters | 参数
    ///
    /// * `c` - Iteration count (minimum 1000, recommended ≥100000)
    ///
    /// ## Iteration Guidelines | 迭代指南
    ///
    /// | Use Case | Iterations | Security Level |
    /// |----------|------------|----------------|
    /// | Legacy   | 10,000     | Minimum        |
    /// | Standard | 100,000    | Good           |
    /// | High Sec | 1,000,000  | High           |
    ///
    /// ## Performance Note | 性能注意
    ///
    /// Higher iteration counts provide better security but increase computation time.
    /// Test on your target hardware to find the right balance.
    ///
    /// 更高的迭代次数提供更好的安全性但增加计算时间。
    /// 在目标硬件上测试以找到正确的平衡。
    pub fn pbkdf2_sha256_with_params(self, c: u32) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2 {
            hash: HashAlgorithmEnum::Sha256,
            c: Some(c),
        }
    }

    /// Selects PBKDF2-SHA384 with custom iteration count.
    ///
    /// 选择使用自定义迭代次数的 PBKDF2-SHA384。
    ///
    /// ## Parameters | 参数
    ///
    /// * `c` - Iteration count for SHA-384 variant
    ///
    /// * `c` - SHA-384 变体的迭代次数
    ///
    /// Higher security level than SHA-256 with moderate performance impact.
    /// 比 SHA-256 更高的安全级别，性能影响适中。
    pub fn pbkdf2_sha384_with_params(self, c: u32) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2 {
            hash: HashAlgorithmEnum::Sha384,
            c: Some(c),
        }
    }

    /// Selects PBKDF2-SHA512 with custom iteration count.
    ///
    /// 选择使用自定义迭代次数的 PBKDF2-SHA512。
    ///
    /// ## Parameters | 参数
    ///
    /// * `c` - Iteration count for SHA-512 variant
    ///
    /// * `c` - SHA-512 变体的迭代次数
    ///
    /// Maximum security level for PBKDF2, optimized for 64-bit platforms.
    /// PBKDF2 的最大安全级别，针对 64 位平台优化。
    pub fn pbkdf2_sha512_with_params(self, c: u32) -> KdfPasswordAlgorithm {
        KdfPasswordAlgorithm::Pbkdf2 {
            hash: HashAlgorithmEnum::Sha512,
            c: Some(c),
        }
    }
}

use crate::wrappers::kdf::passwd::KdfPasswordWrapper;

impl KdfPasswordAlgorithm {
    /// Converts the algorithm enum into a concrete wrapper implementation.
    ///
    /// 将算法枚举转换为具体的包装器实现。
    ///
    /// ## Purpose | 目的
    ///
    /// This method creates a wrapper that implements the password-based KDF algorithm trait,
    /// enabling actual cryptographic operations like key derivation from passwords with
    /// appropriate computational cost to resist brute-force attacks.
    ///
    /// 此方法创建一个实现基于密码的 KDF 算法 trait 的包装器，
    /// 启用实际的密码操作，如从密码派生密钥，并具有适当的计算成本以抵抗暴力攻击。
    ///
    /// ## Returns | 返回值
    ///
    /// A `KdfPasswordWrapper` that can perform:
    /// - Password-based key derivation
    /// - Salt-based key separation
    /// - Configurable computational cost
    /// - Secure password verification
    ///
    /// 可以执行以下操作的 `KdfPasswordWrapper`：
    /// - 基于密码的密钥派生
    /// - 基于盐的密钥分离
    /// - 可配置的计算成本
    /// - 安全密码验证
    ///
    /// ## Examples | 示例
    ///
    /// ```rust
    /// use seal_crypto_wrapper::algorithms::kdf::passwd::KdfPasswordAlgorithm;
    /// use seal_crypto_wrapper::prelude::SecretBox;
    ///
    /// // Argon2 for new applications (recommended)
    /// let argon2_alg = KdfPasswordAlgorithm::build().argon2_default();
    /// let argon2_kdf = argon2_alg.into_kdf_password_wrapper();
    ///
    /// let password = SecretBox::new(Box::from(b"my-secret-password".as_slice()));
    /// let salt = b"random_salt_16_bytes";
    /// let derived_key = argon2_kdf.derive(&password, salt, 32)?;
    ///
    /// // PBKDF2 for compatibility
    /// let pbkdf2_alg = KdfPasswordAlgorithm::build().pbkdf2_sha256_with_params(100000);
    /// let pbkdf2_kdf = pbkdf2_alg.into_kdf_password_wrapper();
    ///
    /// let key2 = pbkdf2_kdf.derive(&password, salt, 32)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// ## Security Best Practices | 安全最佳实践
    ///
    /// When using the wrapper:
    /// 1. **Use Random Salts**: Generate unique salts for each password
    /// 2. **Sufficient Cost**: Use appropriate computational cost parameters
    /// 3. **Secure Storage**: Store salts and derived keys securely
    /// 4. **Regular Updates**: Update cost parameters as hardware improves
    ///
    /// 使用包装器时：
    /// 1. **使用随机盐**: 为每个密码生成唯一盐
    /// 2. **足够成本**: 使用适当的计算成本参数
    /// 3. **安全存储**: 安全存储盐和派生密钥
    /// 4. **定期更新**: 随着硬件改进更新成本参数
    ///
    /// ## Algorithm-Specific Notes | 算法特定注意事项
    ///
    /// ### Argon2
    /// - Memory-hard: requires significant RAM
    /// - Resistant to GPU/ASIC attacks
    /// - Configurable memory/time/parallelism
    ///
    /// ### PBKDF2
    /// - Time-hard: only CPU time cost
    /// - Widely supported and standardized
    /// - Vulnerable to specialized hardware attacks
    ///
    /// ### Argon2
    /// - 内存困难：需要大量 RAM
    /// - 抗 GPU/ASIC 攻击
    /// - 可配置内存/时间/并行度
    ///
    /// ### PBKDF2
    /// - 时间困难：仅 CPU 时间成本
    /// - 广泛支持和标准化
    /// - 易受专用硬件攻击
    ///
    /// ## Performance Considerations | 性能考虑
    ///
    /// - **Argon2**: Higher memory usage, better security
    /// - **PBKDF2**: Lower memory usage, faster on some platforms
    /// - **Parameter Tuning**: Test on target hardware for optimal settings
    ///
    /// - **Argon2**: 更高内存使用，更好安全性
    /// - **PBKDF2**: 更低内存使用，在某些平台上更快
    /// - **参数调优**: 在目标硬件上测试以获得最佳设置
    pub fn into_kdf_password_wrapper(self) -> KdfPasswordWrapper {
        use crate::wrappers::kdf::passwd::{
            Argon2Wrapper, Pbkdf2Sha256Wrapper, Pbkdf2Sha384Wrapper, Pbkdf2Sha512Wrapper,
        };
        match self {
            KdfPasswordAlgorithm::Argon2(Some(params)) => {
                KdfPasswordWrapper::new(Box::new(Argon2Wrapper::new(params.m_cost, params.t_cost, params.p_cost)))
            }
            KdfPasswordAlgorithm::Argon2(None) => {
                KdfPasswordWrapper::new(Box::new(Argon2Wrapper::default()))
            }
            KdfPasswordAlgorithm::Pbkdf2 { hash, c } => {
                match (hash, c) {
                    (HashAlgorithmEnum::Sha256, Some(c)) => {
                        KdfPasswordWrapper::new(Box::new(Pbkdf2Sha256Wrapper::new(c)))
                    }
                    (HashAlgorithmEnum::Sha384, Some(c)) => {
                        KdfPasswordWrapper::new(Box::new(Pbkdf2Sha384Wrapper::new(c)))
                    }
                    (HashAlgorithmEnum::Sha512, Some(c)) => {
                        KdfPasswordWrapper::new(Box::new(Pbkdf2Sha512Wrapper::new(c)))
                    }
                    (HashAlgorithmEnum::Sha256, None) => {
                        KdfPasswordWrapper::new(Box::new(Pbkdf2Sha256Wrapper::default()))
                    }
                    (HashAlgorithmEnum::Sha384, None) => {
                        KdfPasswordWrapper::new(Box::new(Pbkdf2Sha384Wrapper::default()))
                    }
                    (HashAlgorithmEnum::Sha512, None) => {
                        KdfPasswordWrapper::new(Box::new(Pbkdf2Sha512Wrapper::default()))
                    }
                }
            }
        }
    }
}
