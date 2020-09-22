//! SHA-256/SHA-224  
//! https://www.cnblogs.com/mengsuenyan/p/12697811.html#toc  

use crate::sha::generic::const_tables::{SHA256_DIGEST_WSIZE, SHA256_BLOCK_SIZE, SHA256_INIT, SHA256_WORD_LEN, f_ch, f_maj, SHA256_K, SHA256_DIGEST_SIZE, SHA224_INIT, SHA224_BLOCK_SIZE, SHA224_DIGEST_SIZE};
use crate::Digest;

#[derive(Clone)]
pub struct SHA256 {
    digest: [u32; SHA256_DIGEST_WSIZE],
    buf: [u8; SHA256_BLOCK_SIZE],
    idx: usize,
    len: usize,
    is_checked: bool,
}

impl SHA256 {
    pub fn new() -> Self {
        SHA256 {
            digest: SHA256_INIT,
            buf: [0u8; SHA256_BLOCK_SIZE],
            idx: 0,
            len: 0,
            is_checked: false,
        }
    }

    #[inline]
    fn rotate_s0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline]
    fn rotate_s1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline]
    fn rotate_d0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline]
    fn rotate_d1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }


    fn sha256_update(&mut self, data_block: Option<&[u8]>) {
        let data_block = match data_block {
            Some(x) => x,
            None => self.buf.as_ref(),
        };
        let mut chunk = 0;

        let digest = &mut self.digest;
        while chunk < data_block.len() {
            let block = &data_block[chunk..(chunk+SHA256_BLOCK_SIZE)];
            const LEN: usize = SHA256_BLOCK_SIZE / SHA256_WORD_LEN;
            let mut word = [0u32; 64];
            let mut itr = block.iter();
            for i in 0..LEN {
                let v = [*itr.next().unwrap(), *itr.next().unwrap(), *itr.next().unwrap(), *itr.next().unwrap()];
                word[i] = u32::from_be_bytes(v);
            }

            for j in LEN..64 {
                word[j] = Self::rotate_d1(word[j-2]).wrapping_add(word[j-7]).wrapping_add(Self::rotate_d0(word[j-15])).wrapping_add(word[j-16]);
            }

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]);
            for j in 0..64 {
                // if j > 15 {
                //     word[j] = Self::rotate_d1(word[j-2]).wrapping_add(word[j-7]).wrapping_add(Self::rotate_d0(word[j-15])).wrapping_add(word[j-16]);
                // }
                let t1 = h.wrapping_add(Self::rotate_s1(e)).wrapping_add(f_ch(e,f,g)).wrapping_add(SHA256_K[j]).wrapping_add(word[j]);
                let t2 = Self::rotate_s0(a).wrapping_add(f_maj(a,b,c));
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }

            digest[0] = a.wrapping_add(digest[0]);
            digest[1] = b.wrapping_add(digest[1]);
            digest[2] = c.wrapping_add(digest[2]);
            digest[3] = d.wrapping_add(digest[3]);
            digest[4] = e.wrapping_add(digest[4]);
            digest[5] = f.wrapping_add(digest[5]);
            digest[6] = g.wrapping_add(digest[6]);
            digest[7] = h.wrapping_add(digest[7]);
            chunk += SHA256_BLOCK_SIZE;
        }
    }
}

impl Digest for SHA256 {
    fn bits_len(&self) -> usize {
        SHA256_DIGEST_SIZE << 3
    }

    fn write(&mut self, data: &[u8]) {
        let mut bytes = data;
        
        self.len += bytes.len();
        if self.idx > 0 {
            let min = std::cmp::min(SHA256_BLOCK_SIZE - self.idx, bytes.len());
            let dst = &mut self.buf[self.idx..(self.idx+min)];
            let src = &bytes[0..min];
            dst.copy_from_slice(src);
            self.idx += min;
            if self.idx == SHA256_BLOCK_SIZE {
                self.sha256_update(None);
                self.idx = 0;
            }

            bytes = &bytes[min..];
        }

        if bytes.len() > SHA256_BLOCK_SIZE {
            let n = bytes.len() & (!(SHA256_BLOCK_SIZE - 1));
            let data_block = &bytes[0..n];
            self.sha256_update(Some(data_block));
            bytes = &bytes[n..];
        }

        if bytes.len() > 0 {
            let dst = &mut self.buf[..bytes.len()];
            dst.copy_from_slice(bytes);
            self.idx += bytes.len();
        }
        self.is_checked = false;
    }

    fn checksum(&mut self, digest: &mut Vec<u8>) {
        if !self.is_checked {
            let mut tmp = [0u8; SHA256_BLOCK_SIZE];
            tmp[0] = 0x80;
            let len = self.len;
            if len % SHA256_BLOCK_SIZE < 56 {
                self.write(&tmp[0..(56-(len%SHA256_BLOCK_SIZE))]);
            } else {
                self.write(&tmp[0..(64+56-(len%SHA256_BLOCK_SIZE))]);
            }

            let len = (len as u64) << 3;
            let len_bytes = len.to_be_bytes();
            self.write(&len_bytes[..]);
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

#[derive(Clone)]
pub struct SHA224 {
    sha_: SHA256,
}

impl SHA224 {
    pub fn new() -> SHA224 {
        SHA224 {
            sha_: SHA256 {
                digest: SHA224_INIT,
                buf: [0u8; SHA224_BLOCK_SIZE],
                idx: 0,
                len: 0,
                is_checked: false,
            }
        }
    }
}


impl Digest for SHA224 {
    fn bits_len(&self) -> usize {
        SHA224_DIGEST_SIZE << 3
    }

    fn write(&mut self, data: &[u8]) {
        self.sha_.write(data);
    }

    fn checksum(&mut self, digest: &mut Vec<u8>) {
        self.sha_.checksum(digest);
        digest.truncate(SHA224_DIGEST_SIZE);
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}