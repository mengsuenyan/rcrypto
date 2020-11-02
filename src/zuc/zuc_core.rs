use crate::zuc::zuc_const_tables::{KD, S_0, S_1};
use crate::{CryptoError, CryptoErrorKind};

const LFSR_MASK: u32 = 0x7fffffff;

/// ZUC stream cipher algorithm   
/// GM/T 0001-2012
#[derive(Clone)]
pub struct ZUC {
    // lfs4[16]作为缓存
    lfsr: [u32; 17],
    r1: u32,
    r2: u32,
}


impl ZUC {
    #[inline]
    fn generate_lfs4(lfsr: &mut [u32; 17], key: &[u8], iv: &[u8]) {
        lfsr.iter_mut().zip(key.iter().zip(KD.iter().zip(iv.iter()))).for_each(|(s, (&k, (&kd, &iv)))| {
            *s = ((k as u32) << 23) | (((kd & 0x7fff) as u32) << 8) | (iv as u32);
        });
    }

    // 密钥装入
    fn key_schedule(key: &[u8], iv: &[u8]) -> ZUC {
        let mut lfsr = [0u32;17];
        
        Self::generate_lfs4(&mut lfsr, key, iv);

        ZUC {
            lfsr,
            r1: 0,
            r2: 0,
        }
    }
    
    #[inline]
    fn rhl31(a: u32, k: usize) -> u32 {
        ((a << k) | (a >> (31 - k))) & LFSR_MASK
    }

    /// c \mod (2^{31} - 1)
    /// = (c & 0x7fffffff) + (c >> 31)
    #[inline]
    fn add_mod31(a: u32, b: u32) -> u32 {
        let x = a.wrapping_add(b);
        (x & LFSR_MASK) + (x >> 31)
    }
    
    fn lfsr_with_initial_mode(&mut self, u: u32) {
        let lfsr = &mut self.lfsr;
        
        let v = Self::add_mod31(Self::rhl31(lfsr[0], 8), lfsr[0]);
        let v = Self::add_mod31(Self::rhl31(lfsr[4], 20), v);
        let v = Self::add_mod31(Self::rhl31(lfsr[10], 21), v);
        let v = Self::add_mod31(Self::rhl31(lfsr[13], 17), v);
        let v = Self::add_mod31(Self::rhl31(lfsr[15], 15), v);
        let s16 = Self::add_mod31(u, v);
        lfsr[lfsr.len() - 1] = if s16 == 0 {
            LFSR_MASK
        } else {
            s16
        };
        
        for i in 0..(lfsr.len() - 1) {
            lfsr[i] = lfsr[i + 1];
        }
    }
    
    fn lfsr_with_work_mode(&mut self) {
        let lfsr = &mut self.lfsr;
        
        let v = Self::add_mod31(Self::rhl31(lfsr[0], 8), lfsr[0]);
        let v = Self::add_mod31(Self::rhl31(lfsr[4], 20), v);
        let v = Self::add_mod31(Self::rhl31(lfsr[10], 21), v);
        let v = Self::add_mod31(Self::rhl31(lfsr[13], 17), v);
        let v = Self::add_mod31(Self::rhl31(lfsr[15], 15), v);
        lfsr[lfsr.len() - 1] = if v == 0 {
            LFSR_MASK
        } else {
            v
        };
        
        for i in 0..(lfsr.len() - 1) {
            lfsr[i] = lfsr[i + 1];
        }
    }
    
    fn non_linear_f(&mut self, x0: u32, x1: u32, x2: u32) -> u32 {
        let w = (x0 ^ self.r1).wrapping_add(self.r2);
        let w1 = self.r1.wrapping_add(x1);
        let w2 = self.r2 ^ x2;
        self.r1 = Self::sbox(Self::l1((w1 << 16) | (w2 >> 16)));
        self.r2 = Self::sbox(Self::l2((w2 << 16) | (w1 >> 16)));
        
        w
    }
    
    // (X0, X1, X2, X3)
    #[inline]
    fn bit_reconstruction(&self)  -> (u32, u32, u32, u32) {
        const HM: u32 = 0x7fff8000;
        const LM: u32 = 0xffff;
        (
            ((self.lfsr[15] & HM) << 1) | (self.lfsr[14] & LM),
            ((self.lfsr[9] >> 15) | (self.lfsr[11] << 16)),
            ((self.lfsr[5] >> 15) | (self.lfsr[7] << 16)),
            ((self.lfsr[0] >> 15) | (self.lfsr[2] << 16)),
        )
    }
    
    #[inline]
    fn l1(x: u32) -> u32 {
        x ^ x.rotate_left(2) ^ x.rotate_left(10) ^ x.rotate_left(18) ^ x.rotate_left(24)
    }
    
    #[inline]
    fn l2(x: u32) -> u32 {
        x ^ x.rotate_left(8) ^ x.rotate_left(14) ^ x.rotate_left(22) ^ x.rotate_left(30)
    }
    
    #[inline]
    fn sbox(x: u32) -> u32 {
        let idx = x.to_be_bytes();
        let (y0, y1, y2, y3) = (
            S_0[idx[0] as usize], S_1[idx[1] as usize], S_0[idx[2] as usize], S_1[idx[3] as usize]
            );
        u32::from_be_bytes([y0, y1, y2, y3])
    }
    
    fn init_and_first_step(&mut self) {
        let zuc = self;
        
        for _ in 0..32 {
            let (x0, x1, x2, _x3) = zuc.bit_reconstruction();
            let w = zuc.non_linear_f(x0, x1, x2);
            zuc.lfsr_with_initial_mode(w >> 1);
        }

        let (x0, x1, x2, _x3) = zuc.bit_reconstruction();
        zuc.non_linear_f(x0, x1, x2);
        zuc.lfsr_with_work_mode();
    }
    
    pub fn set(&mut self, key: [u8; 16], iv: [u8; 16]) {
        self.set_slice(key.as_ref(), iv.as_ref()).unwrap();
    }
    
    pub fn set_slice(&mut self, key: &[u8], iv: &[u8]) -> Result<(), CryptoError> {
        if key.len() != 16 || iv.len() != 16 {
            Err(CryptoError::new(CryptoErrorKind::InvalidParameter,
                                 format!("The length of key and iv must be the {} in bytes", 16)))
        } else {
            Self::generate_lfs4(&mut self.lfsr, key, iv);
            self.r1 = 0;
            self.r2 = 0;
            
            self.init_and_first_step();

            Ok(())
        }
    }

    pub fn new(key: [u8; 16], iv: [u8; 16]) -> ZUC {
        Self::from_slice(key.as_ref(), iv.as_ref()).unwrap()
    }
    
    pub fn from_slice(key: &[u8], iv: &[u8]) -> Result<ZUC, CryptoError> {
        if key.len() != 16 || iv.len() != 16 {
            Err(CryptoError::new(CryptoErrorKind::InvalidParameter, 
                format!("The length of key and iv must be the {} in bytes", 16)))
        } else {
            let mut zuc = Self::key_schedule(key, iv);
            
            zuc.init_and_first_step();

            Ok(zuc)
        }
    }
    
    pub fn zuc(&mut self) -> u32 {
        let (x0, x1, x2, x3) = self.bit_reconstruction();
        let z = self.non_linear_f(x0, x1, x2) ^ x3;
        self.lfsr_with_work_mode();
        z
    }
}

impl Iterator for ZUC {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.zuc())
    }
}