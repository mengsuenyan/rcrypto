//! AES(Advanced Encryption Standard)
//! FIPS 197  
//! https://www.cnblogs.com/mengsuenyan/p/12697694.html

use crate::crypto_err::{CryptoError, CryptoErrorKind};
use crate::cipher::Cipher;
use crate::aes::AES;

/// 明文数据块的字节长度  
pub(super) const AES_BLOCK_SIZE: usize = 16;

impl AES {
    /// `key` must have a valid length in bytes(AES-128: 16, AES-192: 24, AES-256: 32), otherwise
    /// `CryptoError` will returned.
    pub fn new(key: Vec<u8>) -> std::result::Result<Self, CryptoError> {
        match key.len() {
            16 => {
                let mut tmp =[0u8;16];
                tmp.iter_mut().zip(key.iter()).for_each(|(a, &key)| {
                    *a = key;
                });
                Ok(Self::aes_128(tmp))
            },
            24 => {
                let mut tmp =[0u8;24];
                tmp.iter_mut().zip(key.iter()).for_each(|(a, &key)| {
                    *a = key;
                });
                Ok(Self::aes_192(tmp))
            },
            32 => {
                let mut tmp =[0u8;32];
                tmp.iter_mut().zip(key.iter()).for_each(|(a, &key)| {
                    *a = key;
                });
                Ok(Self::aes_256(tmp))
            },
            _ => {
                Err(CryptoError::new(CryptoErrorKind::InvalidParameter,
                                     format!("Wrong key length: {}, the AES key length(in bits) only can be the 128/192/256", key.len())))
            }
        }
    }
}

impl Cipher for AES {
    type Output = usize;
    
    fn block_size(&self) -> Option<usize> {
        Some(AES_BLOCK_SIZE)
    }

    fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<usize, CryptoError> {
        match plaintext_block.len() {
            AES_BLOCK_SIZE => {
                dst.clear();
                self.crypt_block(dst, plaintext_block);
                Ok(dst.len())
            },
            _ => Err(CryptoError::new(CryptoErrorKind::InvalidParameter, 
                                      format!("Wrong plaintext length: {}, the plaintext block length(in bytes) only can be {}",
                                      plaintext_block.len(), AES_BLOCK_SIZE)))
        }
    }

    fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<usize, CryptoError> {
        match cipher_block.len() {
            AES_BLOCK_SIZE => {
                dst.clear();
                self.decrypt_block(dst, cipher_block);
                Ok(dst.len())
            },
            _ => Err(CryptoError::new(CryptoErrorKind::InvalidParameter,
                                      format!("Wrong ciphertext length: {}, the ciphertext block length(in bytes) only can be {}",
                                              cipher_block.len(), AES_BLOCK_SIZE)))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{AES, Cipher};
    
    #[test]
    fn aes() {
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
        
        cases.iter().for_each(|ele| {
            let cipher = AES::new(ele.0.clone()).unwrap();
            let (mut dst0, mut dst1) = (Vec::new(), Vec::new());
            cipher.encrypt(&mut dst0, (ele.1).as_ref()).unwrap();
            assert_eq!(dst0.as_slice(), (ele.2).as_slice(), "cases=>{:?}", ele.0);
            cipher.decrypt(&mut dst1, (ele.2).as_ref()).unwrap();
            assert_eq!(dst1.as_slice(), (ele.1).as_slice());
        });
        
        assert!(AES::new(vec![0,0,1,2,3]).is_err());
    }

    #[test]
    fn aes128() {
        let cases = [
            (
                // Appendix B.
                [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
                [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34],
                [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32],
            ),
            (
                // Appendix C.1.  AES-128
                [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
                [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a],
            ),
        ];

        for ele in cases.iter() {
            let cipher = AES::aes_128(ele.0);
            let mut dst0 = Vec::new();
            cipher.encrypt(&mut dst0, ele.1.as_ref()).unwrap();
            assert_eq!(dst0.as_slice(), ele.2.as_ref(), "cases=>{:?}", ele.0);
            // println!("{:?}->{:?}", dst0, ele.2);
            let mut dst1 = Vec::new();
            cipher.decrypt(&mut dst1, ele.2.as_ref()).unwrap();
            // println!("{:?}->{:?}", dst1, ele.1);
            assert_eq!(dst1.as_slice(), ele.1.as_ref());
        }
    }

    #[test]
    fn aes192() {
        let cases = [
            (
                // Appendix C.2.  AES-192
                [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,],
                [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                [0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91],
            ),
        ];

        for ele in cases.iter() {
            let cipher = AES::aes_192(ele.0);
            let mut dst0 = Vec::new();
            cipher.encrypt(&mut dst0, ele.1.as_ref()).unwrap();
            assert_eq!(dst0.as_slice(), ele.2.as_ref(), "cases=>{:?}", ele.0);
            // println!("{:?}->{:?}", dst0, ele.2);
            let mut dst1 = Vec::new();
            cipher.decrypt(&mut dst1, ele.2.as_ref()).unwrap();
            // println!("{:?}->{:?}", dst1, ele.1);
            assert_eq!(dst1.as_slice(), ele.1.as_ref());
        }
    }

    #[test]
    fn aes256() {
        let cases = [
            (
                // Appendix C.3.  AES-256
                [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,],
                [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                [0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89],
            ),
        ];

        for ele in cases.iter() {
            let cipher = AES::aes_256(ele.0);
            let mut dst0 = Vec::new();
            cipher.encrypt(&mut dst0, ele.1.as_ref()).unwrap();
            assert_eq!(dst0.as_slice(), ele.2.as_ref(), "cases=>{:?}", ele.0);
            // println!("{:?}->{:?}", dst0, ele.2);
            let mut dst1 = Vec::new();
            cipher.decrypt(&mut dst1, ele.2.as_ref()).unwrap();
            // println!("{:?}->{:?}", dst1, ele.1);
            assert_eq!(dst1.as_slice(), ele.1.as_ref());
        }
    }
}
