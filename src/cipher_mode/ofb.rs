//! OFB (Output Feedback Mode)

use std::marker::PhantomData;
use crate::{Cipher, CryptoError, CryptoErrorKind};
use crate::cipher_mode::{InitialVec, EncryptStream, Pond, DecryptStream};
use std::cell::Cell;

pub struct OFB<C, IV> {
    cur_iv: Vec<u8>,
    buf: Cell<Vec<u8>>,
    cipher: C,
    iv: IV,
    phd: PhantomData<*const u8>,
}

impl<C, IV> OFB<C, IV> 
    where C: Cipher, IV: InitialVec<C> {
    
    pub fn new(c: C, iv: IV) -> Result<Self, CryptoError> {
        let mut iv = iv;
        let len = c.block_size().unwrap_or(1);
        
        let mut cur_iv = Vec::with_capacity(len);
        if let Err(e) = iv.initial_vec(&mut cur_iv) {
            return Err(e);
        } else if c.block_size().is_some() && cur_iv.len() != len {
            return Err(CryptoError::new(CryptoErrorKind::InnerErr,
                                        format!("Wrong IV len: {}, the IV len must be the {} in bytes", cur_iv.len(), c.block_size().unwrap())));
        }
        
        Ok(
            Self {
                cur_iv,
                buf: Cell::new(Vec::with_capacity(len)),
                cipher: c,
                iv,
                phd: PhantomData
            }
        )
    }
    
    pub fn update_iv(&mut self) -> Result<&Vec<u8>, CryptoError> {
        let len = self.cipher.block_size().unwrap_or(1);
        if let Err(e) = self.iv.initial_vec(&mut self.cur_iv) {
            Err(e)
        } else if self.cur_iv.len() != self.cipher.block_size().unwrap_or(self.cur_iv.len()) {
            return Err(CryptoError::new(CryptoErrorKind::InnerErr,
                                        format!("Wrong IV len: {}, the IV len must be the {} in bytes", self.cur_iv.len(), len)));
        } else {
            Ok(&self.cur_iv)
        }
    }
    
    pub fn cur_iv(&self) -> Vec<u8> {
        self.cur_iv.clone()
    }
    
    pub fn set_iv(&mut self, iv: Vec<u8>) -> Result<(), CryptoError> {
        if iv.len() != self.cipher.block_size().unwrap_or(iv.len()) {
            return Err(CryptoError::new(CryptoErrorKind::InnerErr,
                                        format!("Wrong IV len: {}, the IV len must be the {} in bytes", iv.len(), self.cipher.block_size().unwrap())));
        } else {
            let mut iv = iv;
            self.cur_iv.clear();
            self.cur_iv.append(&mut iv);
            Ok(())
        }
    }
    
    pub fn encrypt_stream(self) -> OFBEncrypt<C, IV> {
        let len = self.cipher.block_size().unwrap_or(1);
        OFBEncrypt {
            pond: Vec::with_capacity(len),
            data: Vec::with_capacity(len),
            ij: self.cur_iv.clone(),
            ofb: self,
        }
    }
    
    pub fn decrypt_stream(self) -> OFBDecrypt<C, IV> {
        let len = self.cipher.block_size().unwrap_or(1);
        OFBDecrypt {
            pond: Vec::with_capacity(len),
            data: Vec::with_capacity(len),
            ij: self.cur_iv.clone(),
            ofb: self,
        }
    }
    
    #[inline]
    fn get_buf(&self) -> &mut Vec<u8> {
        unsafe {
            &mut (*self.buf.as_ptr())
        }
    }
    
    fn encrypt_inner(&self, mut data: &[u8], ij: &mut Vec<u8>, dst: &mut Vec<u8>) -> Result<usize, CryptoError> {
        let block_len = self.cipher.block_size().unwrap_or(1);
        let oj = self.get_buf();
        
        while data.len() >= block_len {
            match self.cipher.encrypt(oj, ij.as_slice()) {
                Ok(_) => {
                    let block = &data[..block_len];
                    oj.iter().zip(block.iter()).for_each(|(&a, &b)| {
                        dst.push(a ^ b);
                    });
                    ij.clear();
                    ij.append(oj);
                    data = &data[block_len..];
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }
        
        Ok(dst.len())
    }
}

impl<C, IV> Clone for OFB<C, IV> 
    where C: Cipher + Clone, IV: InitialVec<C> + Clone {
    fn clone(&self) -> Self {
        Self {
            cur_iv: self.cur_iv.clone(),
            buf: Cell::new(Vec::with_capacity(self.cur_iv.len())),
            cipher: self.cipher.clone(),
            iv: self.iv.clone(),
            phd: PhantomData,
        }
    }
}

impl<C, IV> Cipher for OFB<C, IV> 
    where C: Cipher, IV: InitialVec<C> {
    fn block_size(&self) -> Option<usize> {
        self.cipher.block_size()
    }

    fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<usize, CryptoError> {
        dst.clear();
        let block_size = self.cipher.block_size().unwrap_or(1);
        
        let mut ij = self.cur_iv.clone();
        let remain = plaintext_block.len() % block_size;
        self.encrypt_inner(&plaintext_block[..(plaintext_block.len() - remain)], &mut ij, dst)?;

        let oj = self.get_buf();
        match self.cipher.encrypt(oj, ij.as_slice()) {
            Ok(_) => {
                let tmp = &plaintext_block[(plaintext_block.len() - remain)..];
                oj.iter().take(remain).zip(tmp.iter()).for_each(|(&a, &b)| {
                    dst.push(a ^ b);
                });
                Ok(dst.len())
            },
            Err(e) => {
                return Err(e);
            }
        }
    }

    fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<usize, CryptoError> {
        self.encrypt(dst, cipher_block)
    }
}

pub struct OFBEncrypt<C, IV> {
    ofb: OFB<C, IV>,
    data: Vec<u8>,
    pond: Vec<u8>,
    ij: Vec<u8>,
}

pub struct OFBDecrypt<C, IV> {
    ofb: OFB<C, IV>,
    data: Vec<u8>,
    pond: Vec<u8>,
    ij: Vec<u8>,
}

impl_cipher_ofb!(OFBEncrypt, ofb);
impl_fn_reset_ofb!(OFBEncrypt);
impl_cipher_ofb!(OFBDecrypt, ofb);
impl_fn_reset_ofb!(OFBDecrypt);

impl<C, IV> EncryptStream for OFBEncrypt<C, IV> 
    where C: Cipher, IV: InitialVec<C> {
    fn write(&mut self, data: &[u8]) -> Result<Pond, CryptoError> {
        if data.is_empty() {
            Ok(Pond::new(&mut self.pond, false))
        } else {
            let block_len = self.ofb.block_size().unwrap_or(1);
            self.data.extend(data.iter());
            
            match self.ofb.encrypt_inner(self.data.as_slice(), &mut self.ij, &mut self.pond) {
                Ok(_) => {
                    let remain = self.data.len() % block_len;
                    let tmp = self.ofb.get_buf();
                    tmp.clear();
                    tmp.extend(self.data.iter().skip(self.data.len() - remain));
                    self.data.clear();
                    self.data.extend(tmp.iter());
                    Ok(Pond::new(&mut self.pond, false))
                },
                Err(e) => {
                    Err(e)
                }
            }
        }
    }

    fn finish(&mut self) -> Result<Pond, CryptoError> {
        if self.data.is_empty() {
            self.ij.clear();
            self.ij.extend(self.ofb.cur_iv.iter());
            Ok(Pond::new(&mut self.pond, true))
        } else {
            let oj = self.ofb.get_buf();
            match self.ofb.cipher.encrypt(oj, self.ij.as_slice()) {
                Ok(_) => {
                    for (&a, &b) in self.data.iter().zip(oj.iter().take(self.data.len())) {
                        self.pond.push(a ^ b);
                    };
                    self.data.clear();
                    self.ij.clear();
                    self.ij.extend(self.ofb.cur_iv.iter());
                    Ok(Pond::new(&mut self.pond, true))
                },
                Err(e) => Err(e)
            }
        }
    }
}

impl<C, IV> DecryptStream for OFBDecrypt<C, IV> 
    where C: Cipher, IV: InitialVec<C> {
    fn write(&mut self, data: &[u8]) -> Result<Pond, CryptoError> {
        if data.is_empty() {
            Ok(Pond::new(&mut self.pond, false))
        } else {
            let block_len = self.ofb.block_size().unwrap_or(1);
            self.data.extend(data.iter());

            match self.ofb.encrypt_inner(self.data.as_slice(), &mut self.ij, &mut self.pond) {
                Ok(_) => {
                    let remain = self.data.len() % block_len;
                    let tmp = self.ofb.get_buf();
                    tmp.clear();
                    tmp.extend(self.data.iter().skip(self.data.len() - remain));
                    self.data.clear();
                    self.data.extend(tmp.iter());
                    Ok(Pond::new(&mut self.pond, false))
                },
                Err(e) => {
                    Err(e)
                }
            }
        }
    }

    fn finish(&mut self) -> Result<Pond, CryptoError> {
        if self.data.is_empty() {
            self.ij.clear();
            self.ij.extend(self.ofb.cur_iv.iter());
            Ok(Pond::new(&mut self.pond, true))
        } else {
            let oj = self.ofb.get_buf();
            match self.ofb.cipher.encrypt(oj, self.ij.as_slice()) {
                Ok(_) => {
                    for (&a, &b) in self.data.iter().zip(oj.iter().take(self.data.len())) {
                        self.pond.push(a ^ b);
                    };
                    self.data.clear();
                    self.ij.clear();
                    self.ij.extend(self.ofb.cur_iv.iter());
                    Ok(Pond::new(&mut self.pond, true))
                },
                Err(e) => Err(e)
            }
        }
    }
}