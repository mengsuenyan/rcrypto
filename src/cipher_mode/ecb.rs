//! ECB(Electronic Codebook Mode)

use crate::{Cipher, CryptoError, CryptoErrorKind};
use crate::cipher_mode::padding::Padding;
use std::any::TypeId;
use crate::cipher_mode::EmptyPadding;
use std::cell::Cell;
use std::marker::PhantomData;
use crate::cipher_mode::pond::{EncryptStream, Pond, DecryptStream};

/// ECB(Electronic Codebook Mode)
/// 
/// # Usage
/// 
/// ```Rust
/// let key = (0x0123456789ABCDEFu64, 0x23456789ABCDEF01u64, 0x456789ABCDEF0123u64);
/// let tdes = TDES::new(key.0.to_be_bytes(), key.1.to_be_bytes(), key.2.to_be_bytes();
/// let ecb = ECB::new(tdes.clone(), EmptyPadding::new());
/// let decrypt = ecb.clone();   // the instance of ecb can only be used for one of encryption or decryption;
/// let txt = 0x6BC1BEE22E409F96u64;
/// 
/// let mut cipher_txt = Vec::new();
/// ecb.encrypt(&mut cipher_txt, txt.to_be_bytes().as_ref())?;
/// 
/// let mut plain_txt = Vec::new();
/// decrypt.decrypt(&mut plain_txt, cipher_txt.as_slice())?;
/// 
/// // or
/// let mut en = ECB:new(tdes.clone(), EmptyPadding::new()).encrypt_stream();
/// 
/// let txt = vec![0x6BC1BEE22E409F96u64, 0xE93D7E117393172A, 0xAE2D8A571E03AC9C, 0x9EB76FAC45AF8E51,];
/// 
/// txt.iter().for_each(|&x| {
///     en.write(x.to_be_bytes().as_ref()).unwrap();
/// });
/// 
/// cipher_txt.clear();
/// en.finish().unwrap().draw_off(&mut cipher_txt);
/// 
/// 
/// // or
/// let mut en = ECB:new(tdes.clone(), EmptyPadding::new()).encrypt_stream();
/// 
/// let txt = vec![0x6BC1BEE22E409F96u64, 0xE93D7E117393172A, 0xAE2D8A571E03AC9C, 0x9EB76FAC45AF8E51,];
/// 
/// cipher_txt.clear();
/// txt.iter().for_each(|&x| {
///     en.write(x.to_be_bytes().as_ref()).unwrap().draw_off(&mut cipher_txt);
/// });
/// 
/// ```
/// 
/// 
/// 
pub struct ECB<C, P> {
    buf: Cell<Vec<u8>>,
    cipher: C, 
    padding: P,
    phd: PhantomData<*const u8>,
}

impl<C: Cipher, P: Padding> ECB<C, P> {
    pub fn new(cipher: C, padding: P) -> Self {
        let block_size = cipher.block_size().unwrap_or(1);
        Self {
            buf: Cell::new(Vec::with_capacity(block_size)),
            cipher,
            padding,
            phd: PhantomData,
        }
    }
    
    #[inline]
    fn get_buf(&self) -> &mut Vec<u8> {
        unsafe {
            &mut (*self.buf.as_ptr())
        }
    }
    
    pub fn encrypt_stream(self) -> ECBEncrypt<C, P> {
        ECBEncrypt {
            data: Vec::with_capacity(self.cipher.block_size().unwrap_or(1)),
            pond: Vec::with_capacity(self.cipher.block_size().unwrap_or(1)),
            ecb: self,
        }
    }
    
    pub fn decrypt_stream(self) -> ECBDecrypt<C, P> {
        ECBDecrypt {
            data: Vec::with_capacity(self.cipher.block_size().unwrap_or(1)),
            pond: Vec::with_capacity(self.cipher.block_size().unwrap_or(1)),
            ecb: self,
        }
    }
}

impl<C: Cipher, P: 'static + Padding> Cipher for ECB<C, P> {
    fn block_size(&self) -> Option<usize> {
        self.cipher.block_size()
    }

    fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<usize, CryptoError> {
        let block_size = self.cipher.block_size().unwrap_or(1);
        let mut data = plaintext_block;
        let txt = self.get_buf();
        
        dst.clear();
        while data.len() >= block_size {
            let tmp = &data[0..block_size];
            match self.cipher.encrypt(txt, tmp) {
                Ok(_) => {
                    dst.append(txt);
                    data = &data[block_size..];
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }

        let mut tmp= data.to_vec();
        if TypeId::of::<EmptyPadding>() != TypeId::of::<P>() {
            self.padding.padding(&mut tmp);
        }

        let mut data = tmp.as_slice();
        while !data.is_empty() {
            let len = std::cmp::min(data.len(), block_size);
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

        dst.clear();
        while data.len() >= block_size {
            let tmp = &data[0..block_size];
            match self.cipher.decrypt(txt, tmp) {
                Ok(_) => {
                    dst.append(txt);
                    data = &data[block_size..];
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }

        if TypeId::of::<EmptyPadding>() != TypeId::of::<P>() {
            self.padding.unpadding(dst)
        } else {
            Ok(dst.len())
        }
    }
}

impl<C, P> Clone for ECB<C, P>
    where C: Cipher + Clone, P: 'static + Padding + Clone {
    fn clone(&self) -> Self {
        Self {
            buf: Cell::new(Vec::with_capacity(self.block_size().unwrap_or(1))),
            cipher: self.cipher.clone(),
            padding: self.padding.clone(),
            phd: PhantomData,
        }
    }
}

pub struct ECBEncrypt<C, P> {
    ecb: ECB<C, P>,
    data: Vec<u8>,
    pond: Vec<u8>,
}

impl_cipher!(ECBEncrypt, ecb);
impl_fn_reset!(ECBEncrypt);

impl<C, P> EncryptStream for ECBEncrypt<C, P> 
    where C: Cipher, P: 'static + Padding {
    fn write(&mut self, data: &[u8]) -> Result<Pond, CryptoError> {
        let block_len = self.ecb.cipher.block_size().unwrap_or(1);
        let mut data = data;
        
        if data.is_empty() {
            return Ok(Pond::new(&mut self.pond, false));
        } else {
            let len = std::cmp::min(block_len - self.data.len(), data.len());
            self.data.extend(data.iter().take(len));
            data = &data[len..];
        }
        
        let txt = self.ecb.get_buf();
        if self.data.len() == block_len {
            match self.ecb.cipher.encrypt(txt, self.data.as_slice()) {
                Ok(_) => {
                    self.pond.append(txt);
                    self.data.clear();
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }
        
        while data.len() >= block_len {
            let tmp = &data[..block_len];
            match self.ecb.cipher.encrypt(txt, tmp) {
                Ok(_) => {
                    self.pond.append(txt);
                    data = &data[block_len..];
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }
        
        if data.len() > 0 {
            data.iter().for_each(|&e| {self.data.push(e)});
        }
        
        Ok(Pond::new(&mut self.pond, false))
    }

    fn finish(&mut self) -> Result<Pond, CryptoError> {
        if TypeId::of::<EmptyPadding>() != TypeId::of::<P>() {
            self.ecb.padding.padding(&mut self.data);
        }
        
        let block_len = self.ecb.cipher.block_size().unwrap_or(1);
        let txt = self.ecb.get_buf();
        let mut data = self.data.as_slice();
        while !data.is_empty() {
            let len = std::cmp::min(block_len, data.len());
            let tmp = &data[..len];
            match self.ecb.cipher.encrypt(txt, tmp) {
                Ok(_) => {
                    self.pond.append(txt);
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

pub struct ECBDecrypt<C, P> {
    ecb: ECB<C, P>,
    data: Vec<u8>,
    pond: Vec<u8>,
}

impl_cipher!(ECBDecrypt, ecb);
impl_fn_reset!(ECBDecrypt);

impl<C, P> DecryptStream for ECBDecrypt<C, P> 
    where C: Cipher, P: 'static + Padding {
    fn write(&mut self, data: &[u8]) -> Result<Pond, CryptoError> {
        let block_len = self.ecb.cipher.block_size().unwrap_or(1);

        if data.is_empty() {
            return Ok(Pond::new(&mut self.pond, false));
        } else {
            self.data.extend_from_slice(data);
        }

        let txt = self.ecb.get_buf();
        let mut data = self.data.as_slice();
        while data.len() > block_len {
            let tmp = &data[..block_len];
            match self.ecb.cipher.decrypt(txt, tmp) {
                Ok(_) => {
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
        let txt = self.ecb.get_buf();
        match self.ecb.cipher.decrypt(txt, self.data.as_slice()) {
            Ok(_) => {
                if let Err(e) = self.ecb.padding.unpadding(txt) {
                    Err(e)
                } else {
                    self.data.clear();
                    self.pond.append(txt);
                    Ok(Pond::new(&mut self.pond, true))
                }
            },
            Err(e) => {
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::aes::AES;
    use crate::cipher_mode::{DefaultPadding, ECB, EmptyPadding, Padding, EncryptStream};
    use crate::Cipher;

    #[test]
    fn ecb_cipher() {
        let cases = [
            (
                // Appendix B.
                vec![0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
                vec![0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34],
                vec![0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32],
            ),
            (
                // Appendix C.1.  AES-128
                vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
                vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                vec![0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a],
            ),
            (
                // Appendix C.2.  AES-192
                vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,],
                vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                vec![0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91],
            ),
            (
                // Appendix C.3.  AES-256
                vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,],
                vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                vec![0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89],
            ),
        ];
        
        for ele in cases.iter() {
            let cipher = AES::new(ele.0.to_vec()).unwrap();
            let padding = EmptyPadding;
            let ecb = ECB::new(cipher.clone(), padding);
            let (mut dst0, mut dst1) = (Vec::new(), Vec::new());
            ecb.encrypt(&mut dst0, (ele.1).as_ref()).unwrap();
            assert_eq!(dst0.as_slice(), (ele.2).as_slice(), "cases=>{:?}", ele.0);
            ecb.decrypt(&mut dst1, (ele.2).as_ref()).unwrap();
            assert_eq!(dst1.as_slice(), (ele.1).as_slice());


            let padding = DefaultPadding::new(&cipher);
            let ecb = ECB::new(cipher.clone(), padding.clone());
            ecb.encrypt(&mut dst0, (ele.1).as_ref()).unwrap();
            let mut data = (ele.1).to_vec();
            padding.padding(&mut data);
            let mut tmp = Vec::new();
            let mut cdst = Vec::new();
            
            
            let mut data = data.as_slice();
            while !data.is_empty() {
                cipher.encrypt(&mut tmp, &data[0..cipher.block_size().unwrap()]).unwrap();
                cdst.append(&mut tmp);
                data = &data[cipher.block_size().unwrap()..];
            }
            assert_eq!(dst0, cdst, "case: {:?}", ele.0);
            ecb.decrypt(&mut dst1, cdst.as_slice()).unwrap();
            assert_eq!(dst1, (ele.1).as_slice(), "case: {:?}", ele.0);
        }
    }
    
    #[test]
    fn ecb_stream() {
        let cases = [
            (
                // Appendix B.
                vec![0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
                vec![0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34],
                vec![0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32],
            ),
            (
                // Appendix C.1.  AES-128
                vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
                vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                vec![0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a],
            ),
            (
                // Appendix C.2.  AES-192
                vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,],
                vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                vec![0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91],
            ),
            (
                // Appendix C.3.  AES-256
                vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,],
                vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                vec![0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89],
            ),
        ];

        for ele in cases.iter() {
            const ITR: usize = 3;
            let cipher = AES::new(ele.0.to_vec()).unwrap();
            let padding = DefaultPadding::new(&cipher);
            let mut ecb = ECB::new(cipher.clone(), padding.clone()).encrypt_stream();
            let mut dst0 = Vec::new();
            let mut tmp = Vec::new();
            let mut cdst = Vec::new();


            (0..ITR).for_each(|_| {
                ecb.write((ele.1).as_slice()).unwrap().draw_off(&mut dst0);
                cipher.encrypt(&mut tmp, (ele.1).as_slice()).unwrap();
                cdst.append(&mut tmp);
            });
            
            ecb.finish().unwrap().draw_off(&mut dst0);
            
            let mut data = Vec::new();
            padding.padding(&mut data);

            let mut data = data.as_slice();
            while !data.is_empty() {
                cipher.encrypt(&mut tmp, &data[0..cipher.block_size().unwrap()]).unwrap();
                cdst.append(&mut tmp);
                data = &data[cipher.block_size().unwrap()..];
            }
            assert_eq!(dst0, cdst, "case: {:?}", ele.0);
        }
    }
}