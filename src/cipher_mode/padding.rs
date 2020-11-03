use crate::{Cipher, CryptoError, CryptoErrorKind};
use std::marker::PhantomData;

pub trait Padding {
    /// padding the `buf` data in place,
    fn padding(&self, buf: &mut Vec<u8>);
    
    /// unpadding the `buf` data in place, the content will not be changed if error occurred
    fn unpadding(&self, buf: &mut Vec<u8>) -> Result<usize, CryptoError>;
}

/// append a single bit 1 and then append some bit 0;
#[derive(Clone)]
pub struct DefaultPadding<C> {
    block_size: usize,
    phd: PhantomData<C>
}

impl<C: Cipher> DefaultPadding<C> {
    pub fn new(cipher: &C) -> Self {
        DefaultPadding {
            block_size: cipher.block_size().unwrap_or(1),
            phd: PhantomData,
        }
    }
}

impl<C: Cipher> Padding for DefaultPadding<C> {
    fn padding(&self, buf: &mut Vec<u8>) {
        buf.push(0x80);
        let old_len = buf.len();
        if self.block_size < old_len {
            buf.resize(old_len + (self.block_size - (old_len % self.block_size)), 0);
        } else if self.block_size > old_len {
            buf.resize(self.block_size, 0);
        } else {
            buf.resize(self.block_size << 1, 0);
        }
    }

    fn unpadding(&self, buf: &mut Vec<u8>) -> Result<usize, CryptoError> {
        let mut len = 0;
        for &e in buf.iter().rev() {
            if e == 0 {
                len += 1;
            } else if e == 0x80 {
                buf.truncate(buf.len() - len - 1);
                return Ok(buf.len());
            }
        }
        
        Err(CryptoError::new(CryptoErrorKind::UnpaddingNotMatch, 
            format!("unpadding error, not find 0b10*")))
    }
}

/// padding nothing
#[derive(Clone)]
pub struct EmptyPadding;

impl EmptyPadding {
    pub fn new() -> Self {
        EmptyPadding
    }
}

impl Padding for EmptyPadding {
    fn padding(&self, _buf: &mut Vec<u8>) {
    }

    fn unpadding(&self, buf: &mut Vec<u8>) -> Result<usize, CryptoError> {
        Ok(buf.len())
    }
}