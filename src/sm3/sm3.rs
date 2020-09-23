//! SM3 Cryptographic Hash Algorithm  
//! 
//! https://www.cnblogs.com/mengsuenyan/p/13183543.html  

use crate::Digest;

const SM3_BLOCK_BASE2: usize = 6;
const SM3_BLOCK_SIZE: usize = 1 << SM3_BLOCK_BASE2;
const SM3_DIGEST_SIZE: usize = 8;
const SM3_DIGEST_WSIZE: usize = SM3_DIGEST_SIZE << 2;
const IV: [u32;8] = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e];

#[derive(Clone)]
pub struct SM3 {
    digest: [u32; SM3_DIGEST_SIZE],
    buf: [u8; SM3_BLOCK_SIZE],
    idx: usize,
    len: usize,
    is_checked: bool,
}

impl SM3 {
    pub fn new() -> SM3 {
        Self {
            digest: IV,
            buf: [0; SM3_BLOCK_SIZE],
            idx: 0,
            len: 0,
            is_checked: false,
        }
    }
    
    #[inline]
    const fn t_j(round_idx: usize) -> u32 {
        if round_idx < 16 {
            0x79cc4519
        } else {
            0x7a879d8a
        }
    }
    
    #[inline]
    const fn ff_j(round_idx: usize, x: u32, y: u32, z: u32) -> u32 {
        if round_idx < 16 {
            x ^ y ^ z
        } else {
            (x & y) | (x & z) | (y & z)
        }
    }
    
    #[inline]
    const fn gg_j(round_idx: usize, x: u32, y: u32, z: u32) -> u32 {
        if round_idx < 16 {
            x ^ y ^ z
        } else {
            (x & y) | ((!x) & z)
        }
    }
    
    #[inline]
    const fn p_0(x: u32) -> u32 {
        x ^ x.rotate_left(9) ^ x.rotate_left(17)
    }
    
    #[inline]
    const fn p_1(x: u32) -> u32 {
        x ^ x.rotate_left(15) ^ x.rotate_left(23)
    }
    
    fn update(&mut self, data_block: Option<&[u8]>) {
        let data_block = match data_block {
            Some(x) => x,
            None => self.buf.as_ref(),
        };
        
        for i in 0..(data_block.len() >> SM3_BLOCK_BASE2) {
            let mut word = [0u32; SM3_BLOCK_SIZE+4];
            
            data_block.iter().skip(i << SM3_BLOCK_BASE2).take(SM3_BLOCK_SIZE).enumerate().for_each(|(k, &d)| {
                word[k >> 2] = (word[k >> 2] << 8) | (d as u32);
            });
            (16..(SM3_BLOCK_SIZE+4)).for_each(|j| {
                word[j] = Self::p_1(word[j-16] ^ word[j-9] ^ word[j-3].rotate_left(15)) ^ word[j-13].rotate_left(7) ^ word[j-6];
            });
            
            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (self.digest[0], self.digest[1], self.digest[2],
                self.digest[3], self.digest[4], self.digest[5], self.digest[6], self.digest[7]);
            for j in 0..64 {
                let tmp = word[j] ^ word[j+4];
                let s1 = a.rotate_left(12).wrapping_add(e).wrapping_add(Self::t_j(j).rotate_left(j as u32)).rotate_left(7);
                let s2 = s1 ^ a.rotate_left(12);
                let t1 = Self::ff_j(j, a, b, c).wrapping_add(d).wrapping_add(s2).wrapping_add(tmp);
                let t2 = Self::gg_j(j, e, f, g).wrapping_add(h).wrapping_add(s1).wrapping_add(word[j]);
                d = c;
                c = b.rotate_left(9);
                b = a;
                a = t1;
                h = g;
                g = f.rotate_left(19);
                f = e;
                e = Self::p_0(t2);
            }

            self.digest[0] ^= a;
            self.digest[1] ^= b;
            self.digest[2] ^= c;
            self.digest[3] ^= d;
            self.digest[4] ^= e;
            self.digest[5] ^= f;
            self.digest[6] ^= g;
            self.digest[7] ^= h;
        }
    }
}


impl Digest for SM3 {
    fn bits_len(&self) -> usize {
        SM3_DIGEST_WSIZE << 3
    }

    fn write(&mut self, data: &[u8]) {
        let mut data = data;
        self.len += data.len();
        
        if self.idx > 0 {
            let min = std::cmp::min(SM3_BLOCK_SIZE - self.idx, data.len());
            let dst = &mut self.buf[self.idx..(self.idx + min)];
            let src = &data[0..min];
            dst.copy_from_slice(src);
            self.idx += min;
            if self.idx == SM3_BLOCK_SIZE {
                self.update(None);
                self.idx = 0;
            }
            
            data = &data[min..];
        }
        
        if data.len() > SM3_BLOCK_SIZE {
            let n = data.len() & (!(SM3_BLOCK_SIZE - 1));
            let data_block = &data[0..n];
            self.update(Some(data_block));
            data = &data[n..];
        }
        
        if data.len() > 0 {
            let dst = &mut self.buf[..data.len()];
            dst.copy_from_slice(data);
            self.idx += data.len();
        }
        self.is_checked = false;
    }

    fn checksum(&mut self, digest: &mut Vec<u8>) {
        if !self.is_checked {
            let mut tmp = [0u8; SM3_BLOCK_SIZE];
            tmp[0] = 0x80;
            let len = self.len;
            
            if len % SM3_BLOCK_SIZE < 56 {
                self.write(&tmp[0..(56 - (len % SM3_BLOCK_SIZE))]);
            } else {
                self.write(&tmp[0..(64+56-(len % SM3_BLOCK_SIZE))]);
            }
            
            let len = (len as u64) << 3;
            self.write(len.to_be_bytes().as_ref());
            
            self.len = 0;
            self.is_checked = true;
        }
        
        digest.clear();
        self.digest.iter().for_each(|&e| {
            digest.extend(e.to_be_bytes().iter());
        });
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

#[cfg(test)]
mod tests {
    use crate::{SM3, Digest};

    fn cvt_bytes_to_str(b: &[u8]) -> String {
        let mut s= String::new();
        for &ele in b.iter() {
            let e = format!("{:02x}", ele);
            s.push_str(e.as_str());
        }
        s
    }

    #[test]
    fn sm3() {
        let cases = [
            ("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", "abc"),
            ("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732","abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"),
        ];
        
        let mut sm3 = SM3::new();
        let mut digest = Vec::new();
        cases.iter().for_each(|&e| {
            sm3.write(e.1.as_bytes());
            sm3.checksum(&mut digest);
            assert_eq!(e.0, cvt_bytes_to_str(digest.as_slice()), "case: {}", e.1);
            sm3.checksum(&mut digest);
            assert_eq!(e.0, cvt_bytes_to_str(digest.as_slice()), "case: {}", e.1);
            sm3.reset();
        });
    }
}