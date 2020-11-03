//! CFB(Cipher Feedback mode)

use std::cell::Cell;
use crate::{Cipher, CryptoError, CryptoErrorKind};
use crate::cipher_mode::{Padding, InitialVec, EncryptStream, Pond, DecryptStream};
use std::marker::PhantomData;

pub struct CFB<C, P, IV> {
    s: usize,
    buf: Cell<Vec<u8>>,
    cur_iv: Vec<u8>,
    cipher: C,
    padding: P,
    iv: IV,
    phd: PhantomData<*const u8>,
}

impl<C, P, IV> CFB<C, P, IV> 
    where C: Cipher, P: 'static + Padding, IV: InitialVec<C> {
    
    /// parameters need to satisfy the following conditions:  
    /// s(in bits) % 8 == 0;  
    /// 1 <= (s >> 3) <= c.block_size();  
    /// let mut buf = Vec::new(); p.padding(&mut buf); buf.len() == s >> 3;  
    pub fn new(c: C, p: P, iv: IV, s: usize) -> Result<Self, CryptoError> {
        if (s & 7) > 0 {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter,
                                        format!("Wrong s: {}, s % 8 must be equal to 0", s)));
        }
        
        let s = s >> 3;
        if s < 1 || s > c.block_size().unwrap_or(s) {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, 
                format!("Wrong s(in bytes): {}, the s need to satisfy 1 <= s <= {}", s, c.block_size().unwrap_or(s))));
        }
        
        let mut curiv = Vec::new();
        curiv.resize(s, 0);
        p.padding(&mut curiv);
        if (curiv.len() % s) != 0 {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter,
                format!("Wrong padding len: {}, the padding len should be equal to a multiple of s: {}", curiv.len(), s)));
        }
        
        let mut iv = iv;
        if let Err(e) = iv.initial_vec(&mut curiv) {
            return Err(e);
        } else if c.block_size().is_some() && curiv.len() != c.block_size().unwrap() {
            return Err(CryptoError::new(CryptoErrorKind::InnerErr,
                format!("Wrong IV len: {}, the IV len must be the {} in bytes", curiv.len(), c.block_size().unwrap())));
        }
        
        let block_len = c.block_size().unwrap_or(1);
        Ok(Self {
            buf: Cell::new(Vec::with_capacity(block_len)),
            cur_iv: curiv,
            cipher: c,
            padding: p,
            iv,
            s,
            phd: PhantomData,
        })
    }

    /// update initialization vectors
    pub fn update_iv(&mut self) -> Result<&Vec<u8>, CryptoError> {
        let block_len = self.cipher.block_size().unwrap_or(1);
        match self.iv.initial_vec(&mut self.cur_iv) {
            Ok(_) => {
                if self.cipher.block_size().is_some() && block_len != self.cur_iv.len() {
                    Err(CryptoError::new(CryptoErrorKind::InnerErr,
                                         format!("Wrong IV len: {}, the IV len must be the {} in bytes", self.cur_iv.len(), block_len)))
                } else {
                    Ok(&self.cur_iv)
                }
            },
            Err(e) => Err(e),
        }
    }
    
    pub fn cur_iv(&self) -> Vec<u8> {
        self.cur_iv.clone()
    }

    pub fn set_iv(&mut self, iv: Vec<u8>) -> Result<(), CryptoError> {
        let block_len = self.cipher.block_size().unwrap_or(1);
        if self.cipher.block_size().is_some() && iv.len() != block_len {
            Err(CryptoError::new(CryptoErrorKind::InvalidParameter,
                                 format!("Wrong IV len: {}, the IV len must be the {} in bytes", self.cur_iv.len(), block_len)))
        } else {
            let mut iv = iv;
            self.cur_iv.clear();
            self.cur_iv.append(&mut iv);
            Ok(())
        }
    }
    
    #[inline]
    fn get_buf(&self) -> &mut Vec<u8> {
        unsafe {
            &mut (*self.buf.as_ptr())
        }
    }


    pub fn encrypt_stream(self) -> CFBEncrypt<C, P, IV> {
        CFBEncrypt {
            pond: Vec::with_capacity(self.cipher.block_size().unwrap_or(1)),
            data: Vec::with_capacity(self.cipher.block_size().unwrap_or(1)),
            ij: self.cur_iv.clone(),
            cfb: self,
        }
    }

    pub fn decrypt_stream(self) -> CFBDecrypt<C, P, IV> {
        CFBDecrypt {
            pond: Vec::with_capacity(self.cipher.block_size().unwrap_or(1)),
            data: Vec::with_capacity(self.cipher.block_size().unwrap_or(1)),
            ij: self.cur_iv.clone(),
            cfb: self,
        }
    }
    
    fn encrypt_inner(&self, ij: &mut Vec<u8>, dst: &mut Vec<u8>, mut data: &[u8]) -> Result<usize, CryptoError> {
        let oj = self.get_buf();
        while data.len() >= self.s {
            match self.cipher.encrypt(oj, ij.as_slice()) {
                Ok(_) => {
                    let block = &data[..self.s];
                    // $C_j = P_j \oplus MSB_s(O_j)$
                    oj.iter_mut().take(self.s).zip(block.iter()).for_each(|(a, &b)| {
                        *a = (*a) ^ b;
                    });
                    dst.extend(oj.iter().take(self.s));
                    
                    let oj_len = oj.len();
                    // $I_j = LSB_{b-s}(I_{j-1}) | C_j$
                    oj.extend(ij.iter().skip(self.s));
                    ij.clear();
                    ij.extend(oj.iter().skip(oj_len));
                    ij.extend(oj.iter().take(self.s));

                    data = &data[self.s..];
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }
        
        Ok(dst.len())
    }
    
    fn decrypt_inner(&self, ij: &mut Vec<u8>, dst: &mut Vec<u8>, mut data: &[u8]) -> Result<usize, CryptoError> {
        let oj = self.get_buf();
        while !data.is_empty() {
            match self.cipher.encrypt(oj, ij.as_slice()) {
                Ok(_) => {
                    let cj = &data[..self.s];
                    // $P_j = C_j \oplus MSB_s(O_j)$
                    cj.iter().zip(oj.iter().take(self.s)).for_each(|(&a, &b)| {
                        dst.push(a ^ b);
                    });

                    // $I_j = LSB_s(I_{j-1}) | C_{j-1}$
                    oj.clear();
                    oj.extend(ij.iter().skip(self.s));
                    ij.clear();
                    ij.append(oj);
                    ij.extend_from_slice(cj);
                    data = &data[self.s..];
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }
        
        Ok(dst.len())
    }
}

impl<C, P, IV> Cipher for CFB<C, P, IV>
    where C: Cipher, P: 'static + Padding, IV: InitialVec<C> {
    fn block_size(&self) -> Option<usize> {
        self.cipher.block_size()
    }

    fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<usize, CryptoError> {
        let mut ij = self.cur_iv.clone();
        
        dst.clear();
        
        self.encrypt_inner(&mut ij, dst, plaintext_block)?;
        
        let remain = plaintext_block.len() % self.s;
        let mut data = plaintext_block[(plaintext_block.len() - remain)..plaintext_block.len()].to_vec();
        
        self.padding.padding(&mut data);

        self.encrypt_inner(&mut ij, dst, data.as_slice())
    }

    fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<usize, CryptoError> {
        if cipher_block.len() % self.s != 0 {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter,
                format!("Wrong ciphertext len: {}, the ciphertext block length(in bytes) should be equal to {}", cipher_block.len(), self.s)));
        }
        
        dst.clear();
        let mut ij = self.cur_iv.clone();
        
        self.decrypt_inner(&mut ij, dst, cipher_block)?;

        self.padding.unpadding(dst)
    }
}

impl<C, P, IV> Clone for CFB<C, P, IV> 
    where C: Cipher + Clone, P: 'static + Padding + Clone, IV: InitialVec<C> + Clone {
    fn clone(&self) -> Self {
        Self {
            s: self.s,
            buf: Cell::new(Vec::with_capacity(self.cipher.block_size().unwrap_or(1))),
            cur_iv: self.cur_iv.clone(),
            cipher: self.cipher.clone(),
            padding: self.padding.clone(),
            iv: self.iv.clone(),
            phd: PhantomData,
        }
    }
}

pub struct CFBEncrypt<C, P, IV> {
    cfb: CFB<C, P, IV>,
    data: Vec<u8>,
    pond: Vec<u8>,
    ij: Vec<u8>,
}

pub struct CFBDecrypt<C, P, IV> {
    cfb: CFB<C, P, IV>,
    data: Vec<u8>,
    pond: Vec<u8>,
    ij: Vec<u8>,
}

impl_cipher_iv!(CFBEncrypt, cfb);
impl_fn_reset_iv!(CFBEncrypt, cfb);
impl_cipher_iv!(CFBDecrypt, cfb);
impl_fn_reset_iv!(CFBDecrypt, cfb);

impl<C, P, IV> EncryptStream for CFBEncrypt<C, P, IV> 
    where C: Cipher, P: 'static + Padding, IV: InitialVec<C> {
    fn write(&mut self, data: &[u8]) -> Result<Pond, CryptoError> {
        let mut data = data;
        if data.is_empty() {
            return Ok(Pond::new(&mut self.pond, false));
        } else {
            let len = std::cmp::min(self.cfb.s - self.data.len(), data.len());
            self.data.extend(data.iter().take(len));
            data = &data[len..];
        }
        
        if self.data.len() == self.cfb.s {
            if let Err(e) = self.cfb.encrypt_inner(&mut self.ij, &mut self.pond, self.data.as_slice()) {
                return Err(e);
            } else {
                self.data.clear();
            }
        }
        
        if let Err(e) = self.cfb.encrypt_inner(&mut self.ij, &mut self.pond, data) {
            Err(e)
        } else {
            let len = data.len() % self.cfb.s;
            data = &data[(data.len() - len)..];
            self.data.extend_from_slice(data);
            Ok(Pond::new(&mut self.pond, false))
        }
    }

    fn finish(&mut self) -> Result<Pond, CryptoError> {
        self.cfb.padding.padding(&mut self.data);

        if let Err(e) = self.cfb.encrypt_inner(&mut self.ij, &mut self.pond, self.data.as_slice()) {
            Err(e)
        } else {
            self.data.clear();
            self.ij.clear();
            self.ij.extend(self.cfb.cur_iv.iter());
            Ok(Pond::new(&mut self.pond, true))
        }
    }
}

impl<C, P, IV> DecryptStream for CFBDecrypt<C, P, IV> 
    where C: Cipher, P: 'static + Padding, IV: InitialVec<C> {
    fn write(&mut self, data: &[u8]) -> Result<Pond, CryptoError> {
        if data.is_empty() {
            return Ok(Pond::new(&mut self.pond, false));
        } else {
            self.data.extend_from_slice(data);
        }
        
        let bound = self.data.len() - (self.data.len() % self.cfb.s);
        let data = &self.data.as_slice()[..bound];
        
        if let Err(e) = self.cfb.decrypt_inner(&mut self.ij, &mut self.pond, data) {
            Err(e)
        } else {
            let tmp = self.cfb.get_buf();
            tmp.clear();
            tmp.extend_from_slice(&self.data.as_slice()[bound..]);
            self.data.clear();
            self.data.append(tmp);
            Ok(Pond::new(&mut self.pond, false))
        }
    }

    fn finish(&mut self) -> Result<Pond, CryptoError> {
        if let Err(e) = self.cfb.decrypt_inner(&mut self.ij, &mut self.pond, self.data.as_slice()) {
            Err(e)
        } else {
            if let Err(e) = self.cfb.padding.unpadding(&mut self.pond) {
                return Err(e);
            } else {
                self.data.clear();
                self.ij.clear();
                self.ij.extend(self.cfb.cur_iv.iter());
            }
            Ok(Pond::new(&mut self.pond, true))
        }
    }
}