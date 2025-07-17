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
        #[derive(Clone)]
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
        #[derive(Clone, Default)]
        pub struct $wrapper {
            algorithm: $algo,
        }

        impl $trait for $wrapper {
            $($body)*
        }
    };
}

#[cfg(any(
    feature = "asymmetric-kem",
    feature = "asymmetric-signature",
    feature = "asymmetric-key-agreement"
))]
pub mod asymmetric;
#[cfg(feature = "kdf")]
pub mod kdf;
#[cfg(feature = "symmetric")]
pub mod symmetric;
#[cfg(feature = "xof")]
pub mod xof;
