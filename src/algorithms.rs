pub mod symmetric;
pub mod asymmetric;
pub mod signature;
pub mod kdf;
pub mod xof;



use bincode::{Decode, Encode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum HashAlgorithmEnum {
    Sha256,
    Sha384,
    Sha512,
}