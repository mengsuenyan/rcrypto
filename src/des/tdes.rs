//! TDES(Triple Data Encryption Standard)
//! 
//! SP 800-67 r2
//! 
//! SP 800-131A
//! 
//! FIPS 46-3

use crate::{CryptoError, DES, Cipher};
use crate::des::const_tables::DES_BLOCK_SIZE;
use std::cell::Cell;

pub struct TDES {
    des1: DES,
    des2: DES,
    des3: DES,
    buf: Cell<Vec<u8>>,
}

impl Clone for TDES {
    fn clone(&self) -> Self {
        TDES {
            des1: self.des1.clone(),
            des2: self.des2.clone(),
            des3: self.des3.clone(),
            buf: Cell::new(Vec::with_capacity(DES_BLOCK_SIZE)),
        }
    }
}

impl TDES {
    /// Ths SP 800-67 r2 requires that key1, key2 and keys are not equal to each other.  
    /// Ths SP 800-131A requires that key1 not equal to key2, but key3 should equal to key1.  
    pub fn new(key1: [u8; 8], key2: [u8; 8], key3: [u8; 8]) -> TDES {
        TDES {
            des1: DES::new(key1),
            des2: DES::new(key2),
            des3: DES::new(key3),
            buf: Cell::new(Vec::with_capacity(DES_BLOCK_SIZE)),
        }
    }
    
    #[inline]
    fn get_buf(&self) -> &mut Vec<u8> {
        unsafe {
            &mut (*self.buf.as_ptr())
        }
    }
}

impl Cipher for TDES {
    fn block_size(&self) -> Option<usize> {
        self.des1.block_size()
    }

    fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<usize, CryptoError> {
        // E(K3, D(K2, E(K1, block)))
        self.des1.encrypt(dst, plaintext_block)?;
        self.des2.decrypt(self.get_buf(), dst.as_slice())?;
        self.des3.encrypt(dst, self.get_buf())
    }

    fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<usize, CryptoError> {
        // D(K1, E(K2, D(K3, block)))
        self.des3.decrypt(dst, cipher_block)?;
        self.des2.encrypt(self.get_buf(), dst.as_slice())?;
        self.des1.decrypt(dst, self.get_buf())
    }
}

#[cfg(test)]
mod tests {
    use crate::{TDES, Cipher};

    #[test]
    fn tdes() {
        // (key, text, ciphertext)
        let cases = [
            (
                (0x0123456789ABCDEFu64, 0x23456789ABCDEF01u64, 0x0123456789ABCDEFu64), 
                vec![0x6BC1BEE22E409F96u64, 0xE93D7E117393172A, 0xAE2D8A571E03AC9C, 0x9EB76FAC45AF8E51,],
                vec![0x06EDE3D82884090Au64, 0xFF322C19F0518486, 0x730576972A666E58, 0xB6C88CF107340D3D,],
            ),
            (
                (0x0123456789ABCDEFu64, 0x23456789ABCDEF01u64, 0x456789ABCDEF0123u64),
                vec![0x6BC1BEE22E409F96u64, 0xE93D7E117393172A, 0xAE2D8A571E03AC9C, 0x9EB76FAC45AF8E51,],
                vec![0x714772F339841D34, 0x267FCC4BD2949CC3, 0xEE11C22A576A3038, 0x76183F99C0B6DE87],
            ),
        ];
        
        let mut buf = Vec::with_capacity(8);
        for (i, ele) in cases.iter().enumerate() {
            let tdes = TDES::new(ele.0.0.to_be_bytes(), ele.0.1.to_be_bytes(), ele.0.2.to_be_bytes());
            for (j, txt) in ele.1.iter().zip(ele.2.iter()).enumerate() {
                tdes.encrypt(&mut buf, txt.0.to_be_bytes().as_ref()).unwrap();
                assert_eq!(buf.as_slice(), txt.1.to_be_bytes().as_ref(), "encrypt-case: {}-{}", i, j);
                
                tdes.decrypt(&mut buf, txt.1.to_be_bytes().as_ref()).unwrap();
                assert_eq!(buf.as_slice(), txt.0.to_be_bytes().as_ref(), "decrypt-case: {}-{}", i, j);
            }
        }
    }
}