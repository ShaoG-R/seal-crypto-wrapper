//! Extendable Output Function (XOF) algorithm wrappers with streaming output support.
//!
//! 支持流式输出的可扩展输出函数 (XOF) 算法包装器。
//!
//! ## Overview | 概述
//!
//! This module provides concrete implementations of XOF algorithms that can generate
//! variable-length pseudorandom output from input data. XOFs are particularly useful
//! for key derivation, random number generation, and creating masks for cryptographic
//! protocols.
//!
//! 此模块提供 XOF 算法的具体实现，可以从输入数据生成可变长度的伪随机输出。
//! XOF 特别适用于密钥派生、随机数生成和为密码协议创建掩码。
//!
//! ## Supported Algorithms | 支持的算法
//!
//! - **SHAKE-128**: 128-bit security level, high performance
//! - **SHAKE-256**: 256-bit security level, maximum security
//!
//! ## Key Features | 关键特性
//!
//! ### Streaming Output | 流式输出
//! - Generate arbitrary amounts of output data
//! - Read output in chunks for memory efficiency
//! - Stateful readers for continuous generation
//!
//! ### Domain Separation | 域分离
//! - Salt support for key separation
//! - Context information for different use cases
//! - Deterministic output for same inputs
//!
//! ### Performance | 性能
//! - Efficient implementation based on Keccak
//! - Suitable for real-time applications
//! - Low memory overhead
//!
//! ## Usage Examples | 使用示例
//!
//! ### Basic Key Derivation | 基本密钥派生
//!
//! ```rust
//! use seal_crypto_wrapper::algorithms::xof::XofAlgorithm;
//! use seal_crypto_wrapper::prelude::XofAlgorithmTrait;
//!
//! let xof = XofAlgorithm::build().shake256().into_xof_wrapper();
//! let mut reader = xof.reader(b"input_key_material", None, None)?;
//!
//! // Generate different sized keys
//! let key1 = reader.read_boxed(32); // 32-byte key
//! let key2 = reader.read_boxed(16); // 16-byte key
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### With Salt and Context | 使用盐和上下文
//!
//! ```rust
//! use seal_crypto_wrapper::algorithms::xof::XofAlgorithm;
//! use seal_crypto_wrapper::prelude::XofAlgorithmTrait;
//!
//! let xof = XofAlgorithm::build().shake128().into_xof_wrapper();
//! let mut reader = xof.reader(
//!     b"master_key",
//!     Some(b"unique_salt"),
//!     Some(b"application_context")
//! )?;
//!
//! let derived_key = reader.read_boxed(64);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::algorithms::xof::{ShakeVariant, XofAlgorithm};
use crate::error::{Error, Result};
use crate::traits::XofAlgorithmTrait;
use seal_crypto::prelude::{XofDerivation, XofReader};
use seal_crypto::schemes::xof::shake::{Shake128, Shake256};

/// SHAKE-128 algorithm wrapper providing 128-bit security level.
///
/// 提供 128 位安全级别的 SHAKE-128 算法包装器。
///
/// ## Algorithm Properties | 算法属性
///
/// - **Security Level**: 128-bit
/// - **Rate**: 1344 bits (168 bytes per round)
/// - **Capacity**: 256 bits (32 bytes)
/// - **Performance**: High
/// - **Output Length**: Unlimited
///
/// ## Use Cases | 使用场景
///
/// - General-purpose key derivation
/// - Random number generation for most applications
/// - Stream cipher keystream generation
/// - Mask generation functions
///
/// - 通用密钥派生
/// - 大多数应用的随机数生成
/// - 流密码密钥流生成
/// - 掩码生成函数
///
/// ## Performance Characteristics | 性能特征
///
/// SHAKE-128 offers excellent performance due to its higher rate, making it
/// suitable for applications that need to generate large amounts of output data.
///
/// SHAKE-128 由于其更高的速率提供出色的性能，适用于需要生成大量输出数据的应用。
#[derive(Clone, Default, Debug)]
pub struct Shake128Wrapper {
    shake: Shake128,
}

impl Shake128Wrapper {
    /// Creates a new SHAKE-128 wrapper instance.
    ///
    /// 创建新的 SHAKE-128 包装器实例。
    ///
    /// ## Returns | 返回值
    ///
    /// A new wrapper ready for XOF operations with 128-bit security level.
    ///
    /// 准备进行 128 位安全级别 XOF 操作的新包装器。
    pub fn new() -> Self {
        Self {
            shake: Shake128::default(),
        }
    }
}

impl XofAlgorithmTrait for Shake128Wrapper {
    /// Creates a reader for streaming XOF output generation.
    ///
    /// 创建用于流式 XOF 输出生成的读取器。
    ///
    /// ## Parameters | 参数
    ///
    /// * `ikm` - Input key material (any length)
    /// * `salt` - Optional salt for domain separation
    /// * `info` - Optional context information
    ///
    /// * `ikm` - 输入密钥材料（任意长度）
    /// * `salt` - 用于域分离的可选盐
    /// * `info` - 可选上下文信息
    ///
    /// ## Returns | 返回值
    ///
    /// A reader that can generate unlimited amounts of pseudorandom output.
    ///
    /// 可以生成无限量伪随机输出的读取器。
    fn reader<'a>(
        &self,
        ikm: &'a [u8],
        salt: Option<&'a [u8]>,
        info: Option<&'a [u8]>,
    ) -> Result<XofReaderWrapper<'a>> {
        self.shake
            .reader(ikm, salt, info)
            .map(|r| XofReaderWrapper::new(r))
            .map_err(Error::from)
    }

    /// Creates a boxed clone of this wrapper.
    ///
    /// 创建此包装器的 boxed 克隆。
    fn clone_box(&self) -> Box<dyn XofAlgorithmTrait> {
        Box::new(self.clone())
    }

    /// Returns the algorithm identifier.
    ///
    /// 返回算法标识符。
    fn algorithm(&self) -> XofAlgorithm {
        XofAlgorithm::Shake(ShakeVariant::V128)
    }
}

/// SHAKE-256 algorithm wrapper providing 256-bit security level.
///
/// 提供 256 位安全级别的 SHAKE-256 算法包装器。
///
/// ## Algorithm Properties | 算法属性
///
/// - **Security Level**: 256-bit
/// - **Rate**: 1088 bits (136 bytes per round)
/// - **Capacity**: 512 bits (64 bytes)
/// - **Performance**: Medium-High
/// - **Output Length**: Unlimited
///
/// ## Use Cases | 使用场景
///
/// - High-security key derivation
/// - Long-term cryptographic applications
/// - Post-quantum security preparations
/// - High-value data protection
///
/// - 高安全性密钥派生
/// - 长期密码应用
/// - 后量子安全准备
/// - 高价值数据保护
///
/// ## Security Advantages | 安全优势
///
/// SHAKE-256 provides a higher security margin than SHAKE-128, making it
/// suitable for applications that require long-term security or handle
/// highly sensitive data.
///
/// SHAKE-256 提供比 SHAKE-128 更高的安全边际，适用于需要长期安全
/// 或处理高度敏感数据的应用。
#[derive(Clone, Default, Debug)]
pub struct Shake256Wrapper {
    shake: Shake256,
}

impl Shake256Wrapper {
    /// Creates a new SHAKE-256 wrapper instance.
    ///
    /// 创建新的 SHAKE-256 包装器实例。
    ///
    /// ## Returns | 返回值
    ///
    /// A new wrapper ready for XOF operations with 256-bit security level.
    ///
    /// 准备进行 256 位安全级别 XOF 操作的新包装器。
    pub fn new() -> Self {
        Self {
            shake: Shake256::default(),
        }
    }
}

impl XofAlgorithmTrait for Shake256Wrapper {
    fn reader<'a>(
        &self,
        ikm: &'a [u8],
        salt: Option<&'a [u8]>,
        info: Option<&'a [u8]>,
    ) -> Result<XofReaderWrapper<'a>> {
        self.shake
            .reader(ikm, salt, info)
            .map(|r| XofReaderWrapper::new(r))
            .map_err(Error::from)
    }

    fn clone_box(&self) -> Box<dyn XofAlgorithmTrait> {
        Box::new(self.clone())
    }

    fn algorithm(&self) -> XofAlgorithm {
        XofAlgorithm::Shake(ShakeVariant::V256)
    }
}

/// Universal wrapper for XOF algorithms providing runtime algorithm selection.
///
/// 提供运行时算法选择的 XOF 算法通用包装器。
///
/// ## Purpose | 目的
///
/// This wrapper provides a unified interface for all XOF algorithms, allowing
/// runtime algorithm selection while maintaining type safety. It acts as a
/// bridge between algorithm enums and concrete implementations.
///
/// 此包装器为所有 XOF 算法提供统一接口，允许运行时算法选择同时保持类型安全。
/// 它充当算法枚举和具体实现之间的桥梁。
///
/// ## Features | 特性
///
/// - **Runtime Polymorphism**: Switch between algorithms at runtime
/// - **Unified Interface**: Same API for all XOF algorithms
/// - **Streaming Output**: Generate arbitrary amounts of output
/// - **Memory Efficient**: Read output in chunks
///
/// - **运行时多态性**: 在运行时切换算法
/// - **统一接口**: 所有 XOF 算法的相同 API
/// - **流式输出**: 生成任意量的输出
/// - **内存高效**: 分块读取输出
///
/// ## Examples | 示例
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::xof::XofAlgorithm;
/// use seal_crypto_wrapper::prelude::XofAlgorithmTrait;
///
/// // Create from algorithm enum
/// let algorithm = XofAlgorithm::build().shake256();
/// let wrapper = algorithm.into_xof_wrapper();
///
/// // Generate variable-length output
/// let mut reader = wrapper.reader(b"input", None, None)?;
/// let output1 = reader.read_boxed(32);
/// let output2 = reader.read_boxed(64);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```

#[derive(Clone, Debug)]
pub struct XofWrapper {
    algorithm: Box<dyn XofAlgorithmTrait>,
}

impl XofWrapper {
    /// Creates a new XOF wrapper from a boxed trait object.
    ///
    /// 从 boxed trait 对象创建新的 XOF 包装器。
    ///
    /// ## Arguments | 参数
    ///
    /// * `algorithm` - A boxed trait object implementing XOF functionality
    ///
    /// * `algorithm` - 实现 XOF 功能的 boxed trait 对象
    pub fn new(algorithm: Box<dyn XofAlgorithmTrait>) -> Self {
        Self { algorithm }
    }
}

impl XofAlgorithmTrait for XofWrapper {
    fn reader<'a>(
        &self,
        ikm: &'a [u8],
        salt: Option<&'a [u8]>,
        info: Option<&'a [u8]>,
    ) -> Result<XofReaderWrapper<'a>> {
        self.algorithm.reader(ikm, salt, info)
    }

    fn clone_box(&self) -> Box<dyn XofAlgorithmTrait> {
        self.algorithm.clone_box()
    }

    fn algorithm(&self) -> XofAlgorithm {
        self.algorithm.algorithm()
    }
}

/// Streaming reader for XOF output generation.
///
/// XOF 输出生成的流式读取器。
///
/// ## Purpose | 目的
///
/// This wrapper provides a stateful reader that can generate unlimited amounts
/// of pseudorandom output from the XOF algorithm. It maintains internal state
/// to ensure continuous, deterministic output generation.
///
/// 此包装器提供有状态的读取器，可以从 XOF 算法生成无限量的伪随机输出。
/// 它维护内部状态以确保连续、确定性的输出生成。
///
/// ## Features | 特性
///
/// - **Unlimited Output**: Generate any amount of data
/// - **Stateful**: Maintains position for continuous reading
/// - **Memory Efficient**: Read in chunks to manage memory usage
/// - **Deterministic**: Same inputs always produce same output sequence
///
/// - **无限输出**: 生成任意量的数据
/// - **有状态**: 维护位置以进行连续读取
/// - **内存高效**: 分块读取以管理内存使用
/// - **确定性**: 相同输入总是产生相同输出序列
///
/// ## Examples | 示例
///
/// ```rust
/// use seal_crypto_wrapper::algorithms::xof::XofAlgorithm;
/// use seal_crypto_wrapper::prelude::XofAlgorithmTrait;
///
/// let xof = XofAlgorithm::build().shake128().into_xof_wrapper();
/// let mut reader = xof.reader(b"seed", None, None)?;
///
/// // Read different amounts of data
/// let mut buffer = [0u8; 32];
/// reader.read(&mut buffer);
///
/// // Or get owned data
/// let data = reader.read_boxed(64);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct XofReaderWrapper<'a> {
    reader: XofReader<'a>,
}

impl<'a> XofReaderWrapper<'a> {
    /// Creates a new XOF reader wrapper.
    ///
    /// 创建新的 XOF 读取器包装器。
    ///
    /// ## Arguments | 参数
    ///
    /// * `reader` - The underlying XOF reader implementation
    ///
    /// * `reader` - 底层 XOF 读取器实现
    pub fn new(reader: XofReader<'a>) -> Self {
        Self { reader }
    }

    /// Reads XOF output into the provided buffer.
    ///
    /// 将 XOF 输出读取到提供的缓冲区中。
    ///
    /// ## Arguments | 参数
    ///
    /// * `buffer` - Mutable buffer to fill with XOF output
    ///
    /// * `buffer` - 要用 XOF 输出填充的可变缓冲区
    ///
    /// ## Behavior | 行为
    ///
    /// This method fills the entire buffer with pseudorandom data from the XOF.
    /// Subsequent calls will continue from where the previous call left off.
    ///
    /// 此方法用来自 XOF 的伪随机数据填充整个缓冲区。
    /// 后续调用将从上一次调用停止的地方继续。
    pub fn read(&mut self, buffer: &mut [u8]) {
        use seal_crypto::prelude::DigestXofReader;
        self.reader.read(buffer);
    }

    /// Reads XOF output into a new boxed slice.
    ///
    /// 将 XOF 输出读取到新的 boxed 切片中。
    ///
    /// ## Arguments | 参数
    ///
    /// * `n` - Number of bytes to generate
    ///
    /// * `n` - 要生成的字节数
    ///
    /// ## Returns | 返回值
    ///
    /// A boxed slice containing the requested amount of pseudorandom data.
    ///
    /// 包含请求数量伪随机数据的 boxed 切片。
    ///
    /// ## Memory Management | 内存管理
    ///
    /// This method allocates a new buffer for the output. For large amounts
    /// of data, consider using `read()` with a reusable buffer instead.
    ///
    /// 此方法为输出分配新缓冲区。对于大量数据，
    /// 考虑使用带有可重用缓冲区的 `read()` 方法。
    pub fn read_boxed(&mut self, n: usize) -> Box<[u8]> {
        let mut buf = vec![0u8; n].into_boxed_slice();
        self.read(&mut buf);
        buf
    }
}
