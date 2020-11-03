use crate::{Cipher, CryptoError};
use std::marker::PhantomData;

pub struct Pond<'a> {
    pond: &'a mut Vec<u8>,
    is_finish: bool,
    phd: PhantomData<*const u8>,
}

impl<'a> Pond<'a> {
    pub(super) fn new(pond: &'a mut Vec<u8>, is_finish: bool) -> Self {
        Self {
            pond,
            is_finish,
            phd: PhantomData,
        }
    }
    
    /// append all data into the `buf`, and return the length of the new data
    /// 
    /// # Note
    /// 
    /// This method does not clear the buf contents, just append the pond to the tail of buf;
    pub fn draw_off(self, buf: &mut Vec<u8>) -> usize {
        let len = self.pond.len();
        buf.append(self.pond);
        len
    }
}

impl<'a> Drop for Pond<'a> {
    fn drop(&mut self) {
        if self.is_finish {
            self.pond.clear();
        }
    }
}

pub trait EncryptStream: Cipher {
    fn write(&mut self, data: &[u8]) -> Result<Pond, CryptoError>;
    
    /// the pond will be cleared after `pond.drop()` called.
    fn finish(&mut self) -> Result<Pond, CryptoError>;
}

pub trait DecryptStream: Cipher {
    fn write(&mut self, data: &[u8]) -> Result<Pond, CryptoError>;

    /// the pond will be cleared after `pond.drop()` called.
    fn finish(&mut self) -> Result<Pond, CryptoError>;
}