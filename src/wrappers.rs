//! Algorithm wrapper implementations for type-safe cryptographic operations.
//!
//! 用于类型安全密码操作的算法包装器实现。
//!
//! ## Overview | 概述
//!
//! This module provides concrete implementations of cryptographic algorithm traits,
//! wrapping the underlying cryptographic libraries with a unified, type-safe interface.
//! Each wrapper ensures that operations are performed with the correct algorithm
//! and provides runtime verification of key compatibility.
//!
//! 此模块提供密码算法 trait 的具体实现，用统一的类型安全接口包装底层密码库。
//! 每个包装器确保使用正确的算法执行操作，并提供密钥兼容性的运行时验证。
//!
//! ## Design Pattern | 设计模式
//!
//! ### Wrapper Pattern | 包装器模式
//!
//! Each cryptographic algorithm is wrapped in a struct that:
//! - Implements the appropriate trait (e.g., `AeadAlgorithmTrait`)
//! - Provides algorithm-specific functionality
//! - Ensures type safety and prevents misuse
//! - Handles error conversion and validation
//!
//! 每个密码算法都包装在一个结构体中，该结构体：
//! - 实现适当的 trait（例如 `AeadAlgorithmTrait`）
//! - 提供算法特定的功能
//! - 确保类型安全并防止误用
//! - 处理错误转换和验证
//!
//! ### Trait Objects | Trait 对象
//!
//! Wrappers can be converted to trait objects (`Box<dyn Trait>`), enabling:
//! - Runtime polymorphism
//! - Algorithm selection at runtime
//! - Uniform interfaces across different algorithms
//! - Storage in collections
//!
//! 包装器可以转换为 trait 对象（`Box<dyn Trait>`），启用：
//! - 运行时多态性
//! - 运行时算法选择
//! - 不同算法间的统一接口
//! - 在集合中存储
//!
//! ## Macro Utilities | 宏工具
//!
//! The `define_wrapper!` macro provides a standardized way to create wrapper
//! implementations with consistent patterns and reduced boilerplate code.
//!
//! `define_wrapper!` 宏提供了一种标准化的方式来创建包装器实现，
//! 具有一致的模式和减少的样板代码。

/// Macro for defining cryptographic algorithm wrapper structs.
///
/// 用于定义密码算法包装器结构体的宏。
///
/// ## Purpose | 目的
///
/// This macro reduces boilerplate code when creating wrapper implementations
/// by providing standardized patterns for different wrapper types.
///
/// 此宏通过为不同包装器类型提供标准化模式来减少创建包装器实现时的样板代码。
///
/// ## Variants | 变体
///
/// ### Unit Struct Wrapper | 单元结构体包装器
/// ```ignore
/// define_wrapper!(
///     @unit_struct,
///     MyWrapper,
///     MyTrait,
///     { /* trait implementation */ }
/// );
/// ```
///
/// ### Struct with Algorithm Field | 带算法字段的结构体
/// ```ignore
/// define_wrapper!(
///     @struct_with_algorithm,
///     MyWrapper,
///     MyAlgorithm,
///     MyTrait,
///     { fn new(algo: MyAlgorithm) -> Self { Self { algorithm: algo } } },
///     { /* trait implementation */ }
/// );
/// ```
///
/// ### Struct with Default Algorithm | 带默认算法的结构体
/// ```ignore
/// define_wrapper!(
///     @struct_with_algorithm_default,
///     MyWrapper,
///     MyAlgorithm,
///     MyTrait,
///     { /* trait implementation */ }
/// );
/// ```
#[macro_export(local_inner_macros)]
macro_rules! define_wrapper {
    // Case 1: For wrappers with no fields (unit-like struct)
    (
        @unit_struct,
        $wrapper:ident,
        $trait:path,
        { $($body:tt)* }
    ) => {
        #[derive(Clone, Debug, Default)]
        pub struct $wrapper;

        impl $wrapper {
            pub fn new() -> Self {
                Self
            }
        }

        impl From<$wrapper> for Box<dyn $trait> {
            fn from(wrapper: $wrapper) -> Self {
                Box::new(wrapper)
            }
        }

        impl $trait for $wrapper {
            $($body)*
        }
    };
    // Case 2: For wrappers with an 'algorithm' field and custom new()
    (
        @struct_with_algorithm,
        $wrapper:ident,
        $algo:ty,
        $trait:path,
        { $(#[$new_meta:meta])* fn new($($new_args:tt)*) -> Self { $($new_body:tt)* } },
        { $($body:tt)* }
    ) => {
        #[derive(Clone, Debug)]
        pub struct $wrapper {
            algorithm: $algo,
        }

        impl $wrapper {
            $(#[$new_meta])*
            pub fn new($($new_args)*) -> Self {
                $($new_body)*
            }
        }

        impl $trait for $wrapper {
            $($body)*
        }
    };
    // Case 3: For wrappers with an 'algorithm' field using Default
    (
        @struct_with_algorithm_default,
        $wrapper:ident,
        $algo:ty,
        $trait:path,
        { $($body:tt)* }
    ) => {
        #[derive(Clone, Default, Debug)]
        pub struct $wrapper {
            algorithm: $algo,
        }

        impl $trait for $wrapper {
            $($body)*
        }
    };
}

// Asymmetric algorithm wrappers | 非对称算法包装器
#[cfg(any(
    feature = "asymmetric-kem",
    feature = "asymmetric-signature",
    feature = "asymmetric-key-agreement"
))]
pub mod asymmetric;

// Key derivation function wrappers | 密钥派生函数包装器
#[cfg(feature = "kdf")]
pub mod kdf;

// Aead algorithm wrappers | 对称算法包装器
#[cfg(feature = "aead")]
pub mod aead;

// Extendable output function wrappers | 可扩展输出函数包装器
#[cfg(feature = "xof")]
pub mod xof;

// Hash algorithm wrappers | 哈希算法包装器
pub mod hash;