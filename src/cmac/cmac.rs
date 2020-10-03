//! CMAC(Block Cipher-based Message Authentication Code)  
//! SP 800-38B  


use crate::{Cipher, CryptoError, Digest, DES, TDES, CryptoErrorKind};
use std::any::TypeId;
use crate::aes::AES;
use crate::cmac::const_tables::{RB_128, RB_64};

/// CMAC(Block Cipher-based Message Authentication Code)  
/// SP 800-38B  
pub struct CMAC<C> {
    k1: Vec<u8>,
    k2: Vec<u8>,
    data: Vec<u8>,
    nonce: Vec<u8>,
    is_check: bool,
    cipher: C,
}

impl<C: 'static + Cipher> CMAC<C> {
    fn shl_one(l: &Vec<u8>, k1: &mut Vec<u8>) {
        k1.clear();
        let mut cur = (*l.first().unwrap()) << 1;
        
        l.iter().skip(1).for_each(|&a| {
            cur |= a >> 7;
            k1.push(cur);
            cur = a << 1;
        });
        
        k1.push(cur);
    }
    
    fn subkey_gen(c: &C, k1: &mut Vec<u8>, k2: &mut Vec<u8>, rb: &[u8]) -> Result<(), CryptoError> {
        let block_len = c.block_size().unwrap();
        
        k1.resize(block_len, 0);
        c.encrypt(k2, k1.as_slice()).map(|_|{})?;

        Self::shl_one(k2, k1);
        if (k2.first().unwrap() >> 7) > 0 {
            k1.iter_mut().zip(rb.iter()).for_each(|(a, &b)| {
                *a ^= b;
            });
        }
        
        Self::shl_one(k1, k2);
        
        if (k2.first().unwrap() >> 7) > 0 {
            k2.iter_mut().zip(rb.iter()).for_each(|(a, &b)| {
                *a ^= b;
            });
        }
        
        Ok(())
    }
    
    /// `c` must be an instance of the type AES/DES/TDES
    pub fn new(c: C) -> Result<Self, CryptoError> {
        let (b, rb) = if TypeId::of::<C>() == TypeId::of::<AES>() {
            (c.block_size().unwrap(), RB_128.as_ref())
        } else if TypeId::of::<C>() == TypeId::of::<DES>() || TypeId::of::<C>() == TypeId::of::<TDES>() {
            (c.block_size().unwrap(), RB_64.as_ref())
        } else {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "The CMAC current only support AES/DES/TDES."));
        };
        
        let (mut k1, mut k2) = (Vec::with_capacity(b), Vec::with_capacity(b));
        let mut nonce = Vec::new();
        nonce.resize(b, 0);
        Self::subkey_gen(&c, &mut k1, &mut k2, rb).map(|_| {Self {
            k1,
            k2,
            nonce,
            data: Vec::with_capacity(b),
            is_check: false,
            cipher: c,
        }})
    }
}

impl<C: Cipher> Digest for CMAC<C> {
    fn block_size(&self) -> Option<usize> {
        self.cipher.block_size()
    }

    fn bits_len(&self) -> usize {
        self.cipher.block_size().unwrap() << 3
    }

    fn write(&mut self, data: &[u8]) {
        let b = self.block_size().unwrap();
        if self.is_check {
            self.nonce.clear();
            self.nonce.resize(b, 0);
            self.is_check = false;
        }
        
        let data = if (data.len() + self.data.len()) < b {
            self.data.extend_from_slice(data);
            &data[data.len()..]
        } else {
            let len = b - self.data.len();
            self.data.extend_from_slice(&data[..len]);
            &data[len..]
        };
        
        if (self.data.len() + data.len()) > b {
            self.data.iter_mut().zip(self.nonce.iter()).for_each(|(a, &b)| {
                *a ^= b;
            });
            
            self.cipher.encrypt(&mut self.nonce, self.data.as_slice()).unwrap();
            
            while data.len() > b {
                let txt = &data[..b];
                self.data.iter_mut().zip(self.nonce.iter().zip(txt.iter())).for_each(|(a, (&b, &c))| {
                    *a = b ^ c;
                });
                self.cipher.encrypt(&mut self.nonce, self.data.as_slice()).unwrap();
            }
        }
        
        if !data.is_empty() {
            self.data.clear();
            self.data.extend_from_slice(data);
        }
    }

    fn checksum(&mut self, digest: &mut Vec<u8>) {
        if !self.is_check {
            let b = self.block_size().unwrap();
            
            if self.data.len() == b {
                self.data.iter_mut().zip(self.nonce.iter().zip(self.k1.iter())).for_each(|(a, (&b, &c))| {
                    *a = ((*a) ^ c) ^ b;
                });
            } else {
                self.data.push(0x80);
                self.data.resize(b, 0);
                self.data.iter_mut().zip(self.nonce.iter().zip(self.k2.iter())).for_each(|(a, (&b, &c))| {
                    *a = ((*a) ^ c) ^ b;
                });
            }
            
            self.cipher.encrypt(&mut self.nonce, self.data.as_slice()).unwrap();
            
            self.data.clear();
            self.is_check = true;
        }
        
        digest.clear();
        digest.extend(self.nonce.iter());
    }

    fn reset(&mut self) {
        let b = self.block_size().unwrap();
        self.nonce.clear();
        self.nonce.resize(b, 0);
        self.data.clear();
        self.is_check = false;
    }
}