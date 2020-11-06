//! CTR(Counter Mode)

use crate::{Cipher, CryptoError, CryptoErrorKind};
use crate::cipher_mode::{Counter, EncryptStream, Pond, DecryptStream};
use std::marker::PhantomData;
use std::cell::Cell;

pub struct CTR<C, T> {
    buf: Cell<Vec<u8>>,
    cipher: C,
    counter: Cell<T>,
    phd: PhantomData<*const u8>,
}

impl<C, T>  CTR<C, T> 
    where C: Cipher, T: Counter {
    pub fn new(cipher: C, counter: T) -> Result<Self, CryptoError> {
        let block_len = cipher.block_size().unwrap_or(1);
        
        if counter.bits_len() < (block_len << 3) {
            Err(CryptoError::new(CryptoErrorKind::InnerErr, format!("The length of counter value is too short: {}<{} in bits", counter.bits_len(), block_len << 3)))
        } else {
            Ok(
                Self {
                    buf: Cell::new(Vec::with_capacity(block_len)),
                    cipher,
                    counter: Cell::new(counter),
                    phd: PhantomData,
                }
            )
        }
    }

    pub fn set_counter(&mut self, counter: T) -> Result<(), CryptoError> {
        let block_len = self.cipher.block_size().unwrap_or(1);
        if counter.bits_len() < (block_len << 3) {
            Err(CryptoError::new(CryptoErrorKind::InnerErr, format!("The length of counter value is too short: {}<{} in bits", counter.bits_len(), block_len << 3)))
        } else {
            self.counter.set(counter);
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
                    match self.cipher.encrypt(oj, &c.as_slice()[..block_len]) {
                        Ok(_) => {
                            let len = std::cmp::min(block_len,data.len());
                            let block = &data[..len];
                            block.iter().zip(oj.iter()).for_each(|(&a, &b)| {
                                dst.push(a ^ b);
                            });
                            data = &data[len..];
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
    
    pub fn encrypt_stream(self) -> CTREncrypt<C, T> {
        let len = self.cipher.block_size().unwrap_or(1);
        self.get_counter().reset();
        CTREncrypt {
            ctr: self,
            data: Vec::with_capacity(len),
            pond: Vec::with_capacity(len),
        }
    }
    
    pub fn decrypt_stream(self) -> CTRDecrypt<C, T> {
        CTRDecrypt {
            ctr: self.encrypt_stream()
        }
    }
}

impl<C, T> Cipher for CTR<C, T>
    where C: Cipher, T: Counter {
    type Output = usize;
    
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

impl<C, T> Clone for CTR<C, T>
    where C: Cipher + Clone, T: Counter + Clone {
    fn clone(&self) -> Self {
        Self {
            buf: Cell::new(self.get_buf().clone()),
            cipher: self.cipher.clone(),
            counter: Cell::new(self.get_counter().clone()),
            phd: PhantomData,
        }
    }
}

pub struct CTREncrypt<C, T> {
    ctr: CTR<C, T>,
    data: Vec<u8>,
    pond: Vec<u8>,
}

pub struct CTRDecrypt<C, T> {
    ctr: CTREncrypt<C, T>,
}

impl<C, T>  CTREncrypt<C, T> 
    where C: Cipher, T: Counter {
    pub fn reset(&mut self) {
        self.data.clear();
        self.pond.clear();
        self.ctr.get_counter().reset();
    }
}

impl<C, T>  CTRDecrypt<C, T>
    where C: Cipher, T: Counter {
    pub fn reset(&mut self) {
        self.ctr.reset();
    }
}

impl<C, T> Cipher for CTREncrypt<C, T>
    where C: Cipher, T: Counter {
    type Output = usize;
    
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

impl<C, T> Cipher for CTRDecrypt<C, T>
    where C: Cipher, T: Counter {
    type Output = usize;
    
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

impl<C, T> EncryptStream for CTREncrypt<C, T> 
    where C: Cipher, T: Counter {
    fn write(&mut self, data: &[u8]) -> Result<Pond, CryptoError> {
        let block_len = self.ctr.block_size().unwrap_or(1);
        if data.is_empty() {
            Ok(Pond::new(&mut self.pond, false))
        } else {
            self.data.extend(data.iter());

            let remain = self.data.len() % block_len;
            if let Err(e) = self.ctr.encrypt_inner(&self.data.as_slice()[..(self.data.len() - remain)], &mut self.pond) {
                Err(e)
            } else {
                let tmp = self.ctr.get_buf();
                tmp.clear();
                tmp.extend(self.data.iter().skip(self.data.len() - remain));
                self.data.clear();
                self.data.append(tmp);
                Ok(Pond::new(&mut self.pond, false))
            }
        }
    }

    fn finish(&mut self) -> Result<Pond, CryptoError> {
        match self.ctr.encrypt_inner(self.data.as_slice(), &mut self.pond) {
            Ok(_) => {
                self.data.clear();
                Ok(Pond::new(&mut self.pond, true))
            },
            Err(e) => {
                Err(e)
            }
        }
    }
}

impl<C, T> DecryptStream for CTRDecrypt<C, T>
    where C: Cipher, T: Counter {
    fn write(&mut self, data: &[u8]) -> Result<Pond, CryptoError> {
        self.ctr.write(data)
    }

    fn finish(&mut self) -> Result<Pond, CryptoError> {
        self.ctr.finish()
    }
}