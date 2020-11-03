//! CMAC(Block Cipher-based Message Authentication Code)  
//! SP 800-38B  


use crate::{Cipher, CryptoError, Digest, CryptoErrorKind};
use crate::cmac::const_tables::{RB_128, RB_64, RB_32, RB_48, RB_96, RB_160, RB_192, RB_224, RB_256, RB_320, RB_384, RB_448, RB_512, RB_768, RB_1024, RB_2048};

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
        
        if (k1.first().unwrap() >> 7) > 0 {
            k2.iter_mut().zip(rb.iter()).for_each(|(a, &b)| {
                *a ^= b;
            });
        }
        
        Ok(())
    }
    
    fn block_size_to_rb(block_size: usize) -> Option<u32> {
        match block_size {
            4 => Some(RB_32),
            6 => Some(RB_48),
            8 => Some(RB_64),
            12 => Some(RB_96),
            16 => Some(RB_128),
            20 => Some(RB_160),
            24 => Some(RB_192),
            28 => Some(RB_224),
            32 => Some(RB_256),
            40 => Some(RB_320),
            48 => Some(RB_384),
            56 => Some(RB_448),
            64 => Some(RB_512),
            96 => Some(RB_768),
            128 => Some(RB_1024),
            256 => Some(RB_2048),
            _ => None,
        }
    }
    
    pub fn is_support(c: &C) -> bool {
        match c.block_size() {
            Some(b) => Self::block_size_to_rb(b).is_some(),
            None => false,
        }
    }
    
    /// `c` must be satisfied the `CMAC::is_support(&c) == true`
    pub fn new(c: C) -> Result<Self, CryptoError> {
        let (b, rb) = if Self::is_support(&c) {
            let b = c.block_size().unwrap();
            let x = Self::block_size_to_rb(b).unwrap();
            let mut buf = Vec::with_capacity(b);
            buf.resize(b, 0u8);
            buf.iter_mut().rev().zip(x.to_le_bytes().iter()).for_each(|(a, &b)| {
                *a = b;
            });
            (b, buf)
        } else {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, format!("Does not support the block size of {}", std::any::type_name::<C>())));
        };
        
        let (mut k1, mut k2) = (Vec::with_capacity(b), Vec::with_capacity(b));
        let mut nonce = Vec::new();
        nonce.resize(b, 0);
        Self::subkey_gen(&c, &mut k1, &mut k2, rb.as_slice()).map(|_| {Self {
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
        
        let mut data = if (data.len() + self.data.len()) < b {
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
                data = &data[b..];
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