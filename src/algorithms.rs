#[cfg(feature = "asymmetric")]
pub mod asymmetric;
#[cfg(feature = "kdf")]
pub mod kdf;
#[cfg(feature = "signature")]
pub mod signature;
#[cfg(feature = "symmetric")]
pub mod symmetric;
#[cfg(feature = "xof")]
pub mod xof;

#[allow(unused)]
use bincode::{Decode, Encode};

#[allow(unused)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, serde::Serialize, serde::Deserialize,
)]
pub enum HashAlgorithmEnum {
    Sha256,
    Sha384,
    Sha512,
}
