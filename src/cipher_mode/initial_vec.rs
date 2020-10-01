use crate::{CryptoError, Cipher, CryptoErrorKind};
use std::marker::PhantomData;

pub trait InitialVec<C: Cipher> {
    fn initial_vec(&mut self, iv: &mut Vec<u8>) -> std::result::Result<(), CryptoError>;
}

#[derive(Clone)]
pub struct DefaultInitialVec<C, R> {
    block_size: usize,
    rnd: R,
    phd: PhantomData<C>,
}

impl<C: Cipher, R: rmath::rand::Source<u32>> DefaultInitialVec<C, R> {
    pub fn new(cipher: &C, r: R) -> Self {
        Self {
            block_size: cipher.block_size().unwrap_or(0),
            rnd: r,
            phd: PhantomData,
        }
    }
}

impl<C: Cipher, R: rmath::rand::Source<u32>> InitialVec<C> for DefaultInitialVec<C, R> {
    
    fn initial_vec(&mut self, iv: &mut Vec<u8>) -> Result<(), CryptoError> {
        let len = (self.block_size + 3) >> 2;
        
        iv.clear();
        for _ in 0..len {
            match self.rnd.gen() {
                Ok(r) => {
                    iv.append(&mut r.to_be_bytes().to_vec());
                },
                Err(e) => {
                    return Err(CryptoError::new(CryptoErrorKind::RandError, e));
                }
            }
        }
        
        iv.truncate(self.block_size);
        Ok(())
    }
}
