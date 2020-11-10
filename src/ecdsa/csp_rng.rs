use crate::aes::AES;
use crate::cipher_mode::{CTR, DefaultCounter};
use crate::{CryptoError, Cipher};

pub struct CSPRng {
    ctr: CTR<AES, DefaultCounter>,
    buf: Vec<u8>,
}

impl CSPRng {
    pub fn new(key: Vec<u8>, iv: Vec<u8>) -> Result<Self, CryptoError> {
        let aes = AES::new(key)?;
        let block_len = aes.block_size().unwrap();
        let counter = DefaultCounter::new(iv, block_len << 3)?;
        let ctr = CTR::new(aes, counter)?;
        
        Ok(
            Self {
                ctr,
                buf: Vec::with_capacity(block_len),
            }
        )
    }
    
    pub fn read_full(&mut self, dst: &mut Vec<u8>, len: usize) -> Result<(), CryptoError> {
        self.buf.clear();
        self.buf.resize(len, 0);
        self.ctr.encrypt(dst, self.buf.as_slice()).map(|_|{})
    }
}

