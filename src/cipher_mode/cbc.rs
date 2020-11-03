//! CBC(Cipher Block Chaining)
//! 
//! $$
//! C_1 = CIPH_K(P_1 \oplus IV); 
//! C_j = CIPH_K(P_j \oplus C_{j-1}) for j = 2 … n.
//! 
//! P-1 = CIPH^{-1}_{K}(C_1) \oplus IV;
//! P_j = CIPH^{-1}_{K}(C_j) \oplus C_{j-1}	 for j = 2 … n
//! $$

use std::cell::Cell;
use crate::{Cipher, CryptoError, CryptoErrorKind};
use crate::cipher_mode::{Padding, InitialVec, EncryptStream, Pond, DecryptStream};
use std::marker::PhantomData;

pub struct CBC<C, P, IV> {
    buf: Cell<Vec<u8>>,
    cur_iv: Vec<u8>,
    cipher: C,
    padding: P,
    iv: IV,
    phd: PhantomData<*const u8>,
}

impl<C, P, IV> CBC<C, P, IV> 
    where C: Cipher, P: 'static + Padding, IV: InitialVec<C> {
    
    pub fn new(c: C, p: P, iv: IV) -> Result<Self, CryptoError> {
        let mut iv = iv;
        let block_len = c.block_size().unwrap_or(1);
        let mut cur_iv = Vec::with_capacity(block_len);
        
        if let Err(e) = iv.initial_vec(&mut cur_iv) {
            return Err(e);
        } else if c.block_size().is_some() && cur_iv.len() != block_len {
            return Err(CryptoError::new(CryptoErrorKind::InnerErr, 
                format!("Wrong IV len: {}, The IV len must be the {} in bytes", cur_iv.len(), block_len)));
        }
        
        Ok(Self {
            buf: Cell::new(Vec::with_capacity(block_len)),
            cur_iv,
            cipher: c,
            padding: p,
            iv,
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
                                                format!("Wrong IV len: {}, The IV len must be the {} in bytes", self.cur_iv.len(), block_len)))
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
    
    pub fn encrypt_stream(self) -> CBCEncrypt<C, P, IV> {
        CBCEncrypt {
            pond: Vec::with_capacity(self.cipher.block_size().unwrap_or(1)),
            data: Vec::with_capacity(self.cipher.block_size().unwrap_or(1)),
            ij: self.cur_iv.clone(),
            cbc: self,
        }
    }
    
    pub fn decrypt_stream(self) -> CBCDecrypt<C, P, IV> {
        CBCDecrypt {
            pond: Vec::with_capacity(self.cipher.block_size().unwrap_or(1)),
            data: Vec::with_capacity(self.cipher.block_size().unwrap_or(1)),
            ij: self.cur_iv.clone(),
            cbc: self,
        }
    }
    
    #[inline]
    fn get_buf(&self) -> &mut Vec<u8> {
        unsafe {
            &mut (*self.buf.as_ptr())
        }
    }
    
    #[inline]
    fn xor_iv(block: &[u8], cur_iv: &mut Vec<u8>) {
        cur_iv.iter_mut().zip(block.iter()).for_each(|(a, &b)| {
            *a = (*a) ^ b;
        });
    }
}

impl<C, P, IV> Cipher for CBC<C, P, IV>
    where C: Cipher, P: 'static + Padding, IV: InitialVec<C> {
    
    fn block_size(&self) -> Option<usize> {
        self.cipher.block_size()
    }

    fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<usize, CryptoError> {
        let block_len = self.cipher.block_size().unwrap_or(1);
        let mut data = plaintext_block;
        let mut cur_iv = self.cur_iv.to_vec();
        
        let txt = self.get_buf();
        dst.clear();
        while data.len() >= block_len {
            let tmp = &data[..block_len];
            Self::xor_iv(tmp, &mut cur_iv);
            
            match self.cipher.encrypt(txt, cur_iv.as_slice()) {
                Ok(_) => {
                    cur_iv.clear();
                    cur_iv.extend_from_slice(txt.as_slice());
                    dst.append(txt);
                    data = &data[block_len..];
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }

        let mut tmp = data.to_vec();
        self.padding.padding(&mut tmp);

        let mut data = tmp.as_slice();
        while !data.is_empty() {
            let len = std::cmp::min(block_len, data.len());
            let tmp = &data[..len];
            match self.cipher.encrypt(txt, tmp) {
                Ok(_) => {
                    dst.append(txt);
                    data = &data[len..];
                },
                Err(e) => {
                    return Err(e);
                },
            }
        }
        
        Ok(dst.len())
    }

    fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<usize, CryptoError> {
        let block_size = self.cipher.block_size().unwrap_or(1);

        if (cipher_block.len() % block_size) != 0 {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter,
                                        format!("Wrong ciphertext length: {}, the ciphertext block length(in bytes) only can be {}",
                                                cipher_block.len(), block_size)));
        }
        
        let mut data = cipher_block;
        let txt = self.get_buf();
        let mut curiv = self.cur_iv.as_slice();
        
        dst.clear();
        while !data.is_empty() {
            let len = std::cmp::min(block_size, data.len());
            let tmp = &data[..len];
            match self.cipher.decrypt(txt, tmp) {
                Ok(_) => {
                    curiv.iter().zip(txt.iter()).for_each(|(&a, &b)| {
                        dst.push(a ^ b);
                    });
                    curiv = tmp;
                    data = &data[len..];
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }

        self.padding.unpadding(dst)
    }
}

impl<C, P, IV> Clone for CBC<C, P, IV> 
    where C: Cipher + Clone, P: 'static + Padding + Clone, IV: InitialVec<C> + Clone {
    fn clone(&self) -> Self {
        CBC {
            buf: Cell::new(Vec::with_capacity(self.cipher.block_size().unwrap_or(1))),
            cur_iv: self.cur_iv.clone(),
            cipher: self.cipher.clone(),
            padding: self.padding.clone(),
            iv: self.iv.clone(),
            phd: PhantomData,
        }
    }
}

pub struct CBCEncrypt<C, P, IV> {
    cbc: CBC<C, P, IV>,
    data: Vec<u8>,
    pond: Vec<u8>,
    ij: Vec<u8>,
}

pub struct CBCDecrypt<C, P, IV> {
    cbc: CBC<C, P, IV>,
    data: Vec<u8>,
    pond: Vec<u8>,
    ij: Vec<u8>,
}

impl_cipher_iv!(CBCEncrypt, cbc);
impl_fn_reset_iv!(CBCEncrypt, cbc);
impl_cipher_iv!(CBCDecrypt, cbc);
impl_fn_reset_iv!(CBCDecrypt, cbc);

impl<C, P, IV> CBCEncrypt<C, P, IV> 
    where C: Cipher, P: 'static + Padding, IV: InitialVec<C> {
    fn xor_iv(cur: &mut Vec<u8>, block: &[u8], prev: &Vec<u8>) {
        cur.clear();
        block.iter().zip(prev.iter()).for_each(|(&a, &b)| {
            cur.push(a ^ b);
        });
    }
}

impl<C, P, IV> EncryptStream for CBCEncrypt<C, P, IV> 
    where C: Cipher, P: 'static + Padding, IV: InitialVec<C> {
    fn write(&mut self, data: &[u8]) -> Result<Pond, CryptoError> {
        let block_len = self.cbc.cipher.block_size().unwrap_or(1);
        let mut data = data;
        
        if data.is_empty() {
            return Ok(Pond::new(&mut self.pond, false));
        } else {
            let len = std::cmp::min(block_len - self.data.len(), data.len());
            self.data.extend(data.iter().take(len));
            data = &data[len..];
        }
        
        let txt = self.cbc.get_buf();
        if self.data.len() == block_len {
            Self::xor_iv(txt, self.data.as_slice(), &self.ij);
            match self.cbc.cipher.encrypt(&mut self.ij, txt.as_slice()) {
                Ok(_) => {
                    self.pond.extend(self.ij.iter());
                    self.data.clear();
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }
        
        while data.len() >= block_len {
            let tmp = &data[..block_len];
            Self::xor_iv(txt, tmp, &self.ij);
            match self.cbc.cipher.encrypt(&mut self.ij, txt.as_slice()) {
                Ok(_) => {
                    self.pond.extend(self.ij.iter());
                    data = &data[block_len..];
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }
        
        if !data.is_empty() {self.data.extend_from_slice(data);}
        
        Ok(Pond::new(&mut self.pond, false))
    }

    fn finish(&mut self) -> Result<Pond, CryptoError> {
        self.cbc.padding.padding(&mut self.data);

        let block_len = self.cbc.cipher.block_size().unwrap_or(1);
        let txt = self.cbc.get_buf();
        let mut data = self.data.as_slice();
        while !data.is_empty() {
            let len = std::cmp::min(block_len, data.len());
            let tmp = &data[..len];
            Self::xor_iv(txt, tmp, &self.ij);
            match self.cbc.cipher.encrypt(&mut self.ij, txt.as_slice()) {
                Ok(_) => {
                    self.pond.append(&mut self.ij);
                    self.ij.extend(self.cbc.cur_iv.iter());
                    data = &data[len..];
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }
        
        self.data.clear();
        Ok(Pond::new(&mut self.pond, true))
    }
}


impl<C, P, IV> DecryptStream for CBCDecrypt<C, P, IV>
    where C: Cipher, P: 'static + Padding, IV: InitialVec<C> {
    fn write(&mut self, data: &[u8]) -> Result<Pond, CryptoError> {
        let block_len = self.cbc.cipher.block_size().unwrap_or(1);
        
        if data.is_empty() {
            return Ok(Pond::new(&mut self.pond, false));
        } else {
            self.data.extend_from_slice(data);
        }
        
        let txt = self.cbc.get_buf();
        let mut data = self.data.as_slice();
        while data.len() > block_len {
            let tmp = &data[..block_len];
            match self.cbc.cipher.decrypt(txt, tmp) { 
                Ok(_) => {
                    txt.iter_mut().zip(self.ij.iter_mut().zip(tmp.iter())).for_each(|(a, (b, &c))| 
                        {
                            *a ^= *b;
                            *b = c;
                        });
                    self.pond.append(txt);
                    data = &data[block_len..];
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }
        
        let mut data = data.to_vec();
        self.data.clear();
        self.data.append(&mut data);
        Ok(Pond::new(&mut self.pond, false))
    }

    fn finish(&mut self) -> Result<Pond, CryptoError> {
        let txt = self.cbc.get_buf();
        match self.cbc.cipher.decrypt(txt, self.data.as_slice()) {
            Ok(_) => {
                txt.iter_mut().zip(self.ij.iter()).for_each(|(a, &b)| {
                    *a ^= b;
                });
                if let Err(e) = self.cbc.padding.unpadding(txt) {
                    Err(e)
                } else {
                    self.data.clear();
                    self.pond.append(txt);
                    self.ij.clear();
                    self.ij.extend(self.cbc.cur_iv.iter());
                    Ok(Pond::new(&mut self.pond, true))
                }
            },
            Err(e) => Err(e),
        }
    }
}
