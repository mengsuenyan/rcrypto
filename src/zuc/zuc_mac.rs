use crate::zuc::ZUC;
use crate::{CryptoError, CryptoErrorKind, Digest};

pub struct ZUCMac {
    zuc: ZUC,
    ck: [u8; 16],
    iv: [u8; 16],
    key0: u32,
    key1: u32,
    length: usize,
    t: u32,
    is_check: bool,
}

impl ZUCMac {
    /// bearer: only the lowest 5 bits  are valid
    pub fn new(count: u32, bearer: u8, direction: bool, ck: [u8; 16]) -> ZUCMac {
        Self::from_slice(count, bearer, direction, ck.as_ref()).unwrap()
    }

    /// bearer: only the lowest 5 bits  are valid
    pub fn from_slice(count: u32, bearer: u8, direction: bool, ck: &[u8]) -> Result<ZUCMac, CryptoError> {
        if ck.len() != 16 {
            Err(CryptoError::new(CryptoErrorKind::InvalidParameter,
                                 format!("The length of key and iv must be the {} in bytes", 16)))
        } else {
            let count = count.to_be_bytes();
            let mut iv = [0u8; 16];
            iv[0] = count[0]; iv[1] = count[1]; iv[2] = count[2]; iv[3] = count[3];
            iv[4] = bearer << 3;
            iv[8] = iv[0] ^ ((direction as u8) << 7);
            iv[9] = iv[1];
            for i in 2..=5 {
                iv[i + 8] = iv[i];
            }
            iv[14] = iv[6] ^ ((direction as u8) << 7);
            iv[15] = iv[7];

            match ZUC::from_slice(ck, iv.as_ref()) {
                Ok(z) => {
                    let mut tmp = [0u8; 16];
                    tmp.iter_mut().zip(ck.iter()).for_each(|(e, &k)| {
                        *e = k;
                    });
                    Ok(ZUCMac {
                        zuc: z,
                        ck: tmp,
                        iv,
                        key0: 0,
                        key1: 0,
                        length: 0,
                        t: 0,
                        is_check: false,
                    })
                },
                Err(e) => Err(e),
            }
        }
    }
    
    fn is_one(data: &[u8], idx: usize) -> bool {
        let eidx = idx >> 3;
        let tshl = 7 - (idx & 7);
        (data[eidx] & (1 << tshl)) > 0
    }
}

impl Digest for ZUCMac {
    fn block_size(&self) -> Option<usize> {
        None
    }

    fn bits_len(&self) -> usize {
        32
    }

    fn write(&mut self, data: &[u8]) {
        if self.is_check {
            self.reset();
        }
        
        let bound = data.len() << 3;
        
        self.key0 = self.zuc.zuc();
        self.key1 = self.zuc.zuc();
        for i in 0..bound {
            let rem = i & 31;
            if Self::is_one(data, i) {
                if rem == 0 {
                    self.t ^= self.key0;
                } else {
                    self.t ^= (self.key0 << rem) | (self.key1 >> (32 - rem));
                }
            }
            
            if rem == 31 {
                self.key0 = self.key1;
                self.key1 = self.zuc.zuc();
            }
        }
        self.length += bound;
    }

    fn checksum(&mut self, digest: &mut Vec<u8>) {
        if !self.is_check {
            let rem = self.length & 31;
            if rem == 0 {
                self.t ^= self.key0;
                self.t ^= self.key1;
            } else {
                self.t ^= (self.key0 << rem) | (self.key1 >> (32 - rem));
                self.t ^= self.zuc.zuc();
            }

        }
        
        digest.clear();
        digest.extend(self.t.to_be_bytes().iter());
    }

    fn reset(&mut self) {
        self.zuc.set_slice(self.ck.as_ref(), self.iv.as_ref()).unwrap();
        self.key0 = 0;
        self.key1 = 0;
        self.length = 0;
        self.t = 0;
    }
}