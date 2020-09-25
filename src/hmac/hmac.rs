//! HMAC  
//! 
//! FIPS 198-1
//! 
//! https://www.cnblogs.com/mengsuenyan/p/12699175.html


use crate::{Digest, CryptoError, CryptoErrorKind};

const HMAC_IPAD: u8 = 0x36;
const HMAC_OPAD: u8 = 0x5c;

#[derive(Clone)]
pub struct HMAC<D: Digest> {
    df: D,
    k0_i: Vec<u8>,
    k0_o: Vec<u8>,
    buf: Vec<u8>,
}

impl<D: Digest> HMAC<D> {
    fn generate_k0_io(mut key: Vec<u8>, b: usize, digest: &mut D, k0_i: &mut Vec<u8>, k0_o: &mut Vec<u8>) {
        if b > key.len() {
            key.resize(b, 0);
        } else if b < key.len() {
            digest.reset();
            digest.write(key.as_slice());
            digest.checksum(&mut key);
            key.resize(b, 0);
        };

        k0_i.clear();
        k0_o.clear();
        key.iter().for_each(|&k| {
            k0_i.push(k ^ HMAC_IPAD);
            k0_o.push(k ^ HMAC_OPAD);
        });
    }

    pub fn new(key: Vec<u8>, digest: D) -> std::result::Result<Self, CryptoError> {
        let mut digest = digest;
        match digest.block_size() {
            Some(b) => {
                if b < (digest.bits_len() >> 3) {
                    Err(CryptoError::new(CryptoErrorKind::NotSupportUsage,
                                         format!("{} cannot support used in the HMAC", std::any::type_name::<D>())))
                } else {
                    let (mut k0_i, mut k0_o) = (Vec::with_capacity(b), Vec::with_capacity(b));
                    Self::generate_k0_io(key, b, &mut digest, &mut k0_i, &mut k0_o);
                    
                    Ok(
                        Self {
                            df: digest,
                            k0_i,
                            k0_o,
                            buf: Vec::with_capacity(b),
                        }
                    )
                }
            },
            None => {
                Err(CryptoError::new(CryptoErrorKind::NotSupportUsage, 
                    format!("{} cannot support used in the HMAC", std::any::type_name::<D>())))
            }
        }
    }
    
    /// set new `key`
    pub fn set_key(&mut self, key: Vec<u8>) {
        Self::generate_k0_io(key, self.df.block_size().unwrap(), &mut self.df, &mut self.k0_i, &mut self.k0_o);
    }
    
    pub fn mac(&mut self, text: &[u8], results: &mut Vec<u8>) {
        text.iter().for_each(|&e| {
            self.k0_i.push(e);
        });
        
        self.df.reset();
        self.df.write(self.k0_i.as_slice());
        self.df.checksum(&mut self.buf);
        
        for &e in self.buf.iter() {
            self.k0_o.push(e);
        }
        
        self.df.reset();
        self.df.write(self.k0_o.as_slice());
        self.df.checksum(results);
        
        self.k0_o.truncate(self.df.block_size().unwrap());
        self.k0_i.truncate(self.df.block_size().unwrap());
    }
}