use std::cell::Cell;
use crate::sm4::sm4_const_tables::{SBOX, FK, CK};
use crate::{CryptoError, CryptoErrorKind, Cipher};

const SM4_BLOCK_SIZE: usize = 16;

pub struct SM4 {
    rk: Cell<[u32; 32]>,
}

impl SM4 {
    #[inline]
    fn f_tau(x: u32) -> u32 {
        let y = x.to_be_bytes();
        let s = [SBOX[y[0] as usize], SBOX[y[1] as usize], SBOX[y[2] as usize], SBOX[y[3] as usize]];
        u32::from_be_bytes(s)
    }
    
    #[inline]
    fn f_l(x: u32) -> u32 {
        x ^ x.rotate_left(2) ^ x.rotate_left(10) ^ x.rotate_left(18) ^ x.rotate_left(24)
    }
    
    #[inline]
    fn round_f(x0: u32, x1: u32, x2: u32, x3: u32, rk: u32) -> u32 {
        x0 ^ Self::f_l(Self::f_tau(x1 ^ x2 ^ x3 ^ rk))
    }
    
    #[inline]
    fn f_lb(x: u32) -> u32 {
        x ^ x.rotate_left(13) ^ x.rotate_left(23)
    }
    
    fn key_schedule(mk: &[u32]) -> SM4 {
        let mut k = [0u32; 36];
        mk.iter().zip(k.iter_mut()).enumerate().for_each(|(i, (&x, y))| {
            *y = x ^ FK[i]
        });
        
        let mut rk = [0u32; 32];
        for i in 0..32 {
            k[i + 4] = k[i] ^ Self::f_lb(Self::f_tau(k[i+1] ^ k[i+2] ^ k[i+3] ^ CK[i]));
            rk[i] = k[i+4];
        }
        
        SM4 {
            rk: Cell::new(rk)
        }
    }
    
    #[inline]
    fn u8_to_u32(k0: u8, k1: u8, k2: u8, k3: u8) -> u32 {
        ((k0 as u32) << 24) | ((k1 as u32) << 16) | ((k2 as u32) << 8) | (k3 as u32)
    }
    
    pub fn from_slice(key: &[u8]) -> Result<SM4, CryptoError> {
        if key.len() != SM4_BLOCK_SIZE {
            Err(CryptoError::new(CryptoErrorKind::InvalidParameter, 
                format!("The length of key must be 16 in bytes")))
        } else {
            let mk = [
                Self::u8_to_u32(key[0], key[1], key[2], key[3]),
                Self::u8_to_u32(key[4], key[5], key[6], key[7]),
                Self::u8_to_u32(key[8], key[9], key[10], key[11]),
                Self::u8_to_u32(key[12], key[13], key[14], key[15]),
            ];
            Ok(Self::key_schedule(mk.as_ref()))
        }
    }
    
    pub fn new(key: [u8; 16]) -> SM4 {
        Self::from_slice(key.as_ref()).unwrap()
    }
    
    fn get_rk_ref(&self) -> &[u32; 32] {
        unsafe {
            & (*self.rk.as_ptr())
        }
    }
    
    fn ed_inner(&self, dst: &mut Vec<u8>, data: &[u8], rk: fn(&[u32; 32], usize) -> u32) -> Result<usize, CryptoError> {
        if data.len() != SM4_BLOCK_SIZE {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter,
                                        format!("The length of data block must be 16 in bytes")));
        }

        let mut x = [0u32; 36];
        x[0] = Self::u8_to_u32(data[0], data[1], data[2], data[3]);
        x[1] = Self::u8_to_u32(data[4], data[5], data[6], data[7]);
        x[2] = Self::u8_to_u32(data[8], data[9], data[10], data[11]);
        x[3] = Self::u8_to_u32(data[12], data[13], data[14], data[15]);

        for i in 0..32 {
            x[i + 4] = Self::round_f(x[i], x[i+1], x[i+2], x[i+3], rk(self.get_rk_ref(), i));
        }
        dst.clear();
        for i in (32..=35).rev() {
            dst.extend(x[i].to_be_bytes().iter());
        }

        Ok(dst.len())
    }
}

impl Cipher for SM4 {
    fn block_size(&self) -> Option<usize> {
        Some(SM4_BLOCK_SIZE)
    }

    fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<usize, CryptoError> {
        self.ed_inner(dst, plaintext_block, |rk: &[u32; 32], idx: usize| -> u32 {rk[idx]})
    }

    fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<usize, CryptoError> {
        self.ed_inner(dst, cipher_block, |rk: &[u32; 32], idx: usize| -> u32 {rk[31-idx]})
    }
}