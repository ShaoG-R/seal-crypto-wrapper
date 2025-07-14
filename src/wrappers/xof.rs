use crate::traits::XofAlgorithmTrait;
use crate::error::{Error, Result};
use crate::algorithms::{ShakeVariant, XofAlgorithm};
use seal_crypto::prelude::{XofDerivation, XofReader};
use seal_crypto::schemes::xof::shake::{Shake128, Shake256};

#[derive(Clone, Default)]
pub struct Shake128Wrapper {
    shake: Shake128,
}

impl Shake128Wrapper {
    pub fn new() -> Self {
        Self {
            shake: Shake128::default(),
        }
    }
}

impl XofAlgorithmTrait for Shake128Wrapper {
    fn reader<'a>(
        &self,
        ikm: &'a [u8],
        salt: Option<&'a [u8]>,
        info: Option<&'a [u8]>,
    ) -> Result<XofReaderWrapper<'a>> {
        self.shake.reader(ikm, salt, info)
            .map(|r| XofReaderWrapper::new(r))
            .map_err(Error::from)
    }

    fn clone_box(&self) -> Box<dyn XofAlgorithmTrait> {
        Box::new(self.clone())
    }

    fn algorithm(&self) -> XofAlgorithm {
        XofAlgorithm::Shake(ShakeVariant::V128)
    }
}

#[derive(Clone, Default)]
pub struct Shake256Wrapper {
    shake: Shake256,
}

impl Shake256Wrapper {
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

pub struct XofWrapper {
    algorithm: Box<dyn XofAlgorithmTrait>,
}

impl XofWrapper {
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

pub struct XofReaderWrapper<'a> {
    reader: XofReader<'a>,
}

impl<'a> XofReaderWrapper<'a> {
    pub fn new(reader: XofReader<'a>) -> Self {
        Self { reader }
    }

    pub fn read(&mut self, buffer: &mut [u8]) {
        use seal_crypto::prelude::DigestXofReader;
        self.reader.read(buffer);
    }

    pub fn read_boxed(&mut self, n: usize) -> Box<[u8]> {
        let mut buf = vec![0u8; n].into_boxed_slice();
        self.read(&mut buf);
        buf
    }
}