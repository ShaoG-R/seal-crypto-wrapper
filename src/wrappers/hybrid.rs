use crate::algorithms::{
    AsymmetricAlgorithm, SymmetricAlgorithm,
};
use crate::error::Result;
use seal_crypto::zeroize::Zeroizing;
use crate::keys::asymmetric::{TypedAsymmetricKeyPair, TypedAsymmetricPrivateKey, TypedAsymmetricPublicKey};
use crate::keys::symmetric::{SymmetricKey as UntypedSymmetricKey, TypedSymmetricKey};
use crate::traits::{
    AsymmetricAlgorithmTrait, HybridAlgorithmTrait as HybridAlgorithmTrait, SymmetricAlgorithmTrait,
};

#[derive(Clone)]
pub struct HybridAlgorithmWrapper {
    asymmetric_algorithm: Box<dyn AsymmetricAlgorithmTrait>,
    symmetric_algorithm: Box<dyn SymmetricAlgorithmTrait>,
}

impl HybridAlgorithmWrapper {
    pub fn new(
        asymmetric_algorithm: impl Into<Box<dyn AsymmetricAlgorithmTrait>>,
        symmetric_algorithm: impl Into<Box<dyn SymmetricAlgorithmTrait>>,
    ) -> Self {
        Self {
            asymmetric_algorithm: asymmetric_algorithm.into(),
            symmetric_algorithm: symmetric_algorithm.into(),
        }
    }
}

impl HybridAlgorithmTrait for HybridAlgorithmWrapper {
    fn asymmetric_algorithm(&self) -> &dyn AsymmetricAlgorithmTrait {
        self.asymmetric_algorithm.as_ref()
    }

    fn symmetric_algorithm(&self) -> &dyn SymmetricAlgorithmTrait {
        self.symmetric_algorithm.as_ref()
    }

    fn clone_box(&self) -> Box<dyn HybridAlgorithmTrait> {
        Box::new(self.clone())
    }
}

impl AsymmetricAlgorithmTrait for HybridAlgorithmWrapper {
    fn algorithm(&self) -> AsymmetricAlgorithm {
        self.asymmetric_algorithm.algorithm()
    }

    fn encapsulate_key(
        &self,
        public_key: &TypedAsymmetricPublicKey,
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        self.asymmetric_algorithm.encapsulate_key(public_key)
    }

    fn decapsulate_key(
        &self,
        private_key: &TypedAsymmetricPrivateKey,
        encapsulated_key: &Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.asymmetric_algorithm
            .decapsulate_key(private_key, encapsulated_key)
    }

    fn clone_box_asymmetric(&self) -> Box<dyn AsymmetricAlgorithmTrait> {
        Box::new(self.clone())
    }

    fn generate_keypair(&self) -> Result<TypedAsymmetricKeyPair> {
        self.asymmetric_algorithm.generate_keypair()
    }

    fn into_asymmetric_boxed(self) -> Box<dyn AsymmetricAlgorithmTrait> {
        Box::new(self.asymmetric_algorithm)
    }
}

impl SymmetricAlgorithmTrait for HybridAlgorithmWrapper {
    fn algorithm(&self) -> SymmetricAlgorithm {
        self.symmetric_algorithm.algorithm()
    }

    fn encrypt(
        &self,
        key: &TypedSymmetricKey,
        nonce: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.symmetric_algorithm.encrypt(key, nonce, plaintext, aad)
    }

    fn encrypt_to_buffer(
        &self,
        key: &TypedSymmetricKey,
        nonce: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
        aad: Option<&[u8]>,
    ) -> Result<usize> {
        self.symmetric_algorithm
            .encrypt_to_buffer(key, nonce, plaintext, output, aad)
    }

    fn decrypt(
        &self,
        key: &TypedSymmetricKey,
        nonce: &[u8],
        aad: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        self.symmetric_algorithm
            .decrypt(key, nonce, aad, ciphertext)
    }

    fn decrypt_to_buffer(
        &self,
        key: &TypedSymmetricKey,
        nonce: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
        aad: Option<&[u8]>,
    ) -> Result<usize> {
        self.symmetric_algorithm
            .decrypt_to_buffer(key, nonce, ciphertext, output, aad)
    }

    fn generate_typed_key(&self) -> Result<TypedSymmetricKey> {
        self.symmetric_algorithm.generate_typed_key()
    }

    fn generate_untyped_key(&self) -> Result<UntypedSymmetricKey> {
        self.symmetric_algorithm.generate_untyped_key()
    }

    fn clone_box_symmetric(&self) -> Box<dyn SymmetricAlgorithmTrait> {
        Box::new(self.clone())
    }

    fn key_size(&self) -> usize {
        self.symmetric_algorithm.key_size()
    }

    fn nonce_size(&self) -> usize {
        self.symmetric_algorithm.nonce_size()
    }

    fn tag_size(&self) -> usize {
        self.symmetric_algorithm.tag_size()
    }

    fn into_symmetric_boxed(self) -> Box<dyn SymmetricAlgorithmTrait> {
        Box::new(self.symmetric_algorithm)
    }
}
