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
