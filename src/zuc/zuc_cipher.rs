use crate::{Cipher, CryptoError, CryptoErrorKind};
use std::cell::Cell;
use crate::zuc::ZUC;

pub struct ZUCCipher {
    zuc: Cell<ZUC>,
    ck: [u8; 16],
    iv: [u8; 16],
    key: Cell<Vec<u8>>,
}

impl ZUCCipher {
    /// bearer: only the lowest 5 bits  are valid
    pub fn new(count: u32, bearer: u8, direction: bool, ck: [u8; 16]) -> ZUCCipher {
        Self::from_slice(count, bearer, direction, ck.as_ref()).unwrap()
    }
    
    /// bearer: only the lowest 5 bits  are valid
    pub fn from_slice(count: u32, bearer: u8, direction: bool, ck: &[u8]) -> Result<ZUCCipher, CryptoError> {
        if ck.len() != 16 {
            Err(CryptoError::new(CryptoErrorKind::InvalidParameter,
                                 format!("The length of key and iv must be the {} in bytes", 16)))
        } else {
            let mut iv = [0u8; 16];
            let tmp = count.to_be_bytes();
            iv[0] = tmp[0]; iv[1] = tmp[1]; iv[2] = tmp[2]; iv[3] = tmp[3];
            iv[4] = (bearer << 3) | ((direction as u8) << 2);
            for i in 0..5 {
                iv[i + 8] = iv[i];
            }
            
            match ZUC::from_slice(ck, iv.as_ref()) {
                Ok(z) => {
                    let mut tmp = [0u8; 16];
                    tmp.iter_mut().zip(ck.iter()).for_each(|(e, &k)| {
                        *e = k;
                    });
                    Ok(ZUCCipher {
                        zuc: Cell::new(z),
                        ck: tmp,
                        iv,
                        key: Cell::new(Vec::with_capacity(4)),
                    })
                },
                Err(e) => Err(e),
            }
        }
    }
    
    pub fn reset(&mut self) {
        self.zuc.get_mut().set_slice(self.ck.as_ref(), self.iv.as_ref()).unwrap();
        self.key.get_mut().clear();
    }
    
    #[inline]
    fn get_zuc(&self) -> &mut ZUC {
        unsafe  {
            &mut (*self.zuc.as_ptr())
        }
    }
    
    #[inline]
    fn get_key(&self) -> &mut Vec<u8> {
        unsafe {
            &mut (*self.key.as_ptr())
        }
    }
}

impl Cipher for ZUCCipher {
    fn block_size(&self) -> Option<usize> {
        None
    }

    fn encrypt(&self, dst: &mut Vec<u8>, mut plaintext_block: &[u8]) -> Result<usize, CryptoError> {
        dst.clear();
        let len = std::cmp::min(self.get_key().len(), plaintext_block.len());
        self.get_key().iter().zip(plaintext_block.iter()).for_each(|(&k, &ibs)| {
            dst.push(k ^ ibs);
        });
        
        plaintext_block = &plaintext_block[len..];
        let key = self.get_key();
        for (i, j) in (len..key.len()).zip(0..key.len()) {
            key[j] = key[i];
        }
        self.get_key().truncate(self.get_key().len() - len);
        
        if plaintext_block.is_empty() {
            return Ok(0);
        }

        let len = (plaintext_block.len() + 3) >> 2;
        
        let zuc = self.get_zuc();
        let mut itr = plaintext_block.iter();
        zuc.take(len - 1).for_each(|key| {
            key.to_be_bytes().iter().for_each(|&k| {
                dst.push(k ^ (*itr.next().unwrap()));
            });
        });
        
        let key = self.get_key();
        zuc.zuc().to_be_bytes().iter().for_each(|&k| {
            match itr.next() {
                Some(&ibs) => dst.push(k ^ ibs),
                None => key.push(k),
            }
        });
        
        Ok(dst.len())
    }

    fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<usize, CryptoError> {
        self.encrypt(dst, cipher_block)
    }
}