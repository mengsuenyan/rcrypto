//! CTR(Counter Mode)

use crate::{Cipher, CryptoError, CryptoErrorKind};
use crate::cipher_mode::{Counter, InitialVec, EncryptStream, Pond, DecryptStream};
use std::marker::PhantomData;
use std::cell::Cell;

pub struct CTR<C, T, IV> {
    buf: Cell<Vec<u8>>,
    init_val: Vec<u8>,
    cipher: C,
    counter: Cell<T>,
    iv: IV,
    phd: PhantomData<*const u8>,
}

impl<C, T, IV>  CTR<C, T, IV> 
    where C: Cipher, T: Counter, IV: InitialVec<C> {
    pub fn new(cipher: C, mut counter: T, mut iv: IV) -> Result<Self, CryptoError> {
        let block_len = cipher.block_size().unwrap_or(1);
        let buf = Cell::new(Vec::with_capacity(block_len));
        let mut init_val = Vec::with_capacity(block_len);
        
        match iv.initial_vec(&mut init_val) {
            Ok(_) => {
                if init_val.len() != cipher.block_size().unwrap_or(init_val.len()) {
                    Err(CryptoError::new(CryptoErrorKind::InnerErr,
                                         format!("Wrong IV len: {}, the IV len must be the {} in bytes", init_val.len(), block_len)))
                } else {
                    counter.reset(init_val.clone(), init_val.len() << 3);

                    Ok(
                        Self {
                            buf,
                            init_val,
                            cipher,
                            counter: Cell::new(counter),
                            iv,
                            phd: PhantomData,
                        }
                    )
                }
            },
            Err(e) => {
                Err(e)
            }
        }
    }

    /// update initialization vectors
    pub fn update_iv(&mut self) -> Result<&Vec<u8>, CryptoError> {
        let block_len = self.cipher.block_size().unwrap_or(1);
        match self.iv.initial_vec(&mut self.init_val) {
            Ok(_) => {
                if self.cipher.block_size().is_some() && block_len != self.init_val.len() {
                    Err(CryptoError::new(CryptoErrorKind::InnerErr,
                                         format!("Wrong IV len: {}, the IV len must be the {} in bytes", self.init_val.len(), block_len)))
                } else {
                    self.get_counter().reset(self.init_val.clone(), self.init_val.len() << 3);
                    Ok(&self.init_val)
                }
            },
            Err(e) => Err(e),
        }
    }

    pub fn cur_iv(&self) -> Vec<u8> {
        self.init_val.clone()
    }

    pub fn set_iv(&mut self, iv: Vec<u8>) -> Result<(), CryptoError> {
        let block_len = self.cipher.block_size().unwrap_or(1);
        if self.cipher.block_size().is_some() && iv.len() != block_len {
            Err(CryptoError::new(CryptoErrorKind::InvalidParameter,
                                 format!("Wrong IV len: {}, the IV len must be the {} in bytes", self.init_val.len(), block_len)))
        } else {
            let iv = iv;
            self.init_val.clear();
            self.init_val.extend_from_slice(iv.as_slice());
            self.get_counter().reset(iv, self.init_val.len() << 3);
            
            Ok(())
        }
    }

    #[inline]
    fn get_buf(&self) -> &mut Vec<u8> {
        unsafe {
            &mut (*self.buf.as_ptr())
        }
    }
    
    #[inline]
    fn get_counter(&self) -> &mut T {
        unsafe {
            &mut (*self.counter.as_ptr())
        }
    }
    
    fn encrypt_inner(&self, mut data: &[u8], dst: &mut Vec<u8>) -> Result<usize, CryptoError> {
        let block_len = self.cipher.block_size().unwrap_or(1);
        let oj = self.get_buf();
        while !data.is_empty() {
            match self.get_counter().next() {
                Some(c) => {
                    match self.cipher.encrypt(oj, c.as_slice()) {
                        Ok(_) => {
                            let block = &data[..block_len];
                            block.iter().zip(oj.iter()).for_each(|(&a, &b)| {
                                dst.push(a ^ b);
                            });
                            data = &data[block_len..];
                        },
                        Err(e) => {
                            return Err(e);
                        }
                    }
                },
                None => {
                    return Err(CryptoError::new(CryptoErrorKind::InnerErr,
                                                format!("counter next is none")));
                }
            }
        }

        Ok(dst.len())
    }
    
    pub fn encrypt_stream(self) -> CTREncrypt<C, T, IV> {
        let len = self.cipher.block_size().unwrap_or(1);
        self.get_counter().reset(self.init_val.clone(), len << 3);
        CTREncrypt {
            ctr: self,
            data: Vec::with_capacity(len),
            pond: Vec::with_capacity(len),
        }
    }
    
    pub fn decrypt_stream(self) -> CTRDecrypt<C, T, IV> {
        let len = self.cipher.block_size().unwrap_or(1);
        self.get_counter().reset(self.init_val.clone(), len << 3);
        
        CTRDecrypt {
            ctr: self,
            data: Vec::with_capacity(len),
            pond: Vec::with_capacity(len),
        }
    }
}

impl<C, T, IV> Cipher for CTR<C, T, IV>
    where C: Cipher, T: Counter, IV: InitialVec<C> {
    fn block_size(&self) -> Option<usize> {
        self.cipher.block_size()
    }

    fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<usize, CryptoError> {
        dst.clear();
        self.encrypt_inner(plaintext_block, dst)
    }

    fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<usize, CryptoError> {
        dst.clear();
        
        self.encrypt_inner(cipher_block, dst)
    }
}

impl<C, T, IV> Clone for CTR<C, T, IV>
    where C: Cipher + Clone, T: Counter + Clone, IV: InitialVec<C> + Clone {
    fn clone(&self) -> Self {
        Self {
            buf: Cell::new(self.get_buf().clone()),
            init_val: self.init_val.clone(),
            cipher: self.cipher.clone(),
            counter: Cell::new(self.get_counter().clone()),
            iv: self.iv.clone(),
            phd: PhantomData,
        }
    }
}

pub struct CTREncrypt<C, T, IV> {
    ctr: CTR<C, T, IV>,
    data: Vec<u8>,
    pond: Vec<u8>,
}

pub struct CTRDecrypt<C, T, IV> {
    ctr: CTR<C, T, IV>,
    data: Vec<u8>,
    pond: Vec<u8>,
}

impl<C, T, IV>  CTREncrypt<C, T, IV> 
    where C: Cipher, T: Counter, IV: InitialVec<C> {
    pub fn reset(&mut self) {
        self.data.clear();
        self.pond.clear();
        self.ctr.get_counter().reset(self.ctr.init_val.clone(), self.ctr.block_size().unwrap_or(1) << 3);
    }
}

impl<C, T, IV>  CTRDecrypt<C, T, IV>
    where C: Cipher, T: Counter, IV: InitialVec<C> {
    pub fn reset(&mut self) {
        self.data.clear();
        self.pond.clear();
        self.ctr.get_counter().reset(self.ctr.init_val.clone(), self.ctr.block_size().unwrap_or(1) << 3);
    }
}

impl<C, T, IV> Cipher for CTREncrypt<C, T, IV>
    where C: Cipher, T: Counter, IV: InitialVec<C> {
    fn block_size(&self) -> Option<usize> {
        self.ctr.block_size()
    }

    fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<usize, CryptoError> {
        self.ctr.encrypt(dst, plaintext_block)
    }

    fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<usize, CryptoError> {
        self.ctr.decrypt(dst, cipher_block)
    }
}

impl<C, T, IV> Cipher for CTRDecrypt<C, T, IV>
    where C: Cipher, T: Counter, IV: InitialVec<C> {
    fn block_size(&self) -> Option<usize> {
        self.ctr.block_size()
    }

    fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<usize, CryptoError> {
        self.ctr.encrypt(dst, plaintext_block)
    }

    fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<usize, CryptoError> {
        self.ctr.decrypt(dst, cipher_block)
    }
}

impl<C, T, IV> EncryptStream for CTREncrypt<C, T, IV> 
    where C: Cipher, T: Counter, IV: InitialVec<C> {
    fn write(&mut self, data: &[u8]) -> Result<Pond, CryptoError> {
        let block_len = self.ctr.block_size().unwrap_or(1);
        if data.is_empty() {
            Ok(Pond::new(&mut self.pond, false))
        } else {
            let len = (data.len() + self.data.len()) % block_len;
            let remain = if len == 0 {
                self.data.extend_from_slice(data);
                &data[data.len()..]
            } else {
                self.data.extend_from_slice(&data[..(data.len() - len)]);
                &data[(data.len() - len)..]
            };

            if let Err(e) = self.ctr.encrypt_inner(self.data.as_slice(), &mut self.pond) {
                Err(e)
            } else {
                self.data.clear();
                self.data.extend_from_slice(remain);
                Ok(Pond::new(&mut self.pond, false))
            }
        }
    }

    fn finish(&mut self) -> Result<Pond, CryptoError> {
        match self.ctr.encrypt_inner(self.data.as_slice(), &mut self.pond) {
            Ok(_) => {
                self.data.clear();
                self.ctr.get_counter().reset(self.ctr.cur_iv(), self.ctr.block_size().unwrap_or(1));
                Ok(Pond::new(&mut self.pond, true))
            },
            Err(e) => {
                Err(e)
            }
        }
    }
}

impl<C, T, IV> DecryptStream for CTRDecrypt<C, T, IV>
    where C: Cipher, T: Counter, IV: InitialVec<C> {
    fn write(&mut self, data: &[u8]) -> Result<Pond, CryptoError> {
        if data.is_empty() {
            Ok(Pond::new(&mut self.pond, false))
        } else {
            let block_len = self.ctr.block_size().unwrap_or(1);
            let len = (self.data.len() + data.len()) % block_len;
            let remain = if len == 0 {
                self.data.extend_from_slice(data);
                &data[data.len()..]
            } else {
                let bound = data.len() - len;
                self.data.extend(data.iter().take(bound));
                &data[bound..]
            };
            
            match self.ctr.encrypt_inner(self.data.as_slice(), &mut self.pond) {
                Ok(_) => {
                    self.data.clear();
                    self.data.extend_from_slice(remain);
                    Ok(Pond::new(&mut self.pond, false))
                },
                Err(e) => {
                    Err(e)
                }
            }
        }
    }

    fn finish(&mut self) -> Result<Pond, CryptoError> {
        match self.ctr.encrypt_inner(self.data.as_slice(), &mut self.pond) {
            Ok(_) => {
                self.data.clear();
                self.ctr.get_counter().reset(self.ctr.cur_iv(), self.ctr.block_size().unwrap_or(1));
                Ok(Pond::new(&mut self.pond, false))
            },
            Err(e) => {
                Err(e)
            }
        }
    }
}