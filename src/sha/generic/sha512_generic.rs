//! SHA-512/SHA-384  
//! SHA-512/224  
//! SHA-512/256  
//! https://www.cnblogs.com/mengsuenyan/p/12697811.html

use crate::sha::generic::const_tables::{SHA512_DIGEST_WSIZE, SHA512_BLOCK_SIZE, SHA512_INIT, f_maj, f_ch, SHA512_K, SHA512_DIGEST_SIZE, SHA512_384INIT, SHA512T384_DIGEST_SIZE, SHA512_256INIT, SHA512_224INIT,
    SHA512T256_DIGEST_SIZE, SHA512T224_DIGEST_SIZE};
use crate::Digest;

#[derive(Clone)]
pub struct SHA512 {
    digest: [u64; SHA512_DIGEST_WSIZE],
    buf: [u8; SHA512_BLOCK_SIZE],
    idx: usize,
    len: usize,
    is_checked: bool,
}

impl SHA512 {
    pub fn new() -> Self {
        SHA512 {
            digest: SHA512_INIT,
            buf: [0u8; SHA512_BLOCK_SIZE],
            idx: 0,
            len: 0,
            is_checked: false,
        }
    }

    #[inline]
    fn rotate_s0(x: u64) -> u64 {
        x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
    }

    #[inline]
    fn rotate_s1(x: u64) -> u64 {
        x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
    }

    #[inline]
    fn rotate_d0(x: u64) -> u64 {
        x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
    }

    #[inline]
    fn rotate_d1(x: u64) -> u64 {
        x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
    }

    fn sha512_update(&mut self, data_block: Option<&[u8]>) {
        let data_block = match data_block {
            Some(x) => x,
            None => self.buf.as_ref(),
        };
        let mut chunk = 0;

        let digest = &mut self.digest;
        while chunk < data_block.len() {
            let bytes = &data_block[chunk..(chunk+SHA512_BLOCK_SIZE)];
            let mut word = [0u64; 80];
            let mut itr = bytes.iter();
            for i in 0..16 {
                let v = [*itr.next().unwrap(), *itr.next().unwrap(), *itr.next().unwrap(), *itr.next().unwrap(),
                    *itr.next().unwrap(), *itr.next().unwrap(), *itr.next().unwrap(), *itr.next().unwrap()];
                word[i] = u64::from_be_bytes(v);
            }

            for i in 16..80 {
                word[i] = Self::rotate_d1(word[i-2]).wrapping_add(word[i-7]).wrapping_add(Self::rotate_d0(word[i-15])).wrapping_add(word[i-16]);
            }

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (digest[0], digest[1], digest[2], digest[3], digest[4],
                                                                            digest[5], digest[6], digest[7]);

            for j in 0..80 {
                let t1 = h.wrapping_add(Self::rotate_s1(e)).wrapping_add(f_ch(e,f,g)).wrapping_add(SHA512_K[j]).wrapping_add(word[j]);
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
            chunk += SHA512_BLOCK_SIZE;
        }
    }
}

impl Digest for SHA512 {
    fn bits_len(&self) -> usize {
        SHA512_DIGEST_SIZE << 3
    }

    fn write(&mut self, data: &[u8]) {
        let mut bytes = data;

        self.len += bytes.len();
        if self.idx > 0 {
            let min = std::cmp::min(SHA512_BLOCK_SIZE - self.idx, bytes.len());
            let dst = &mut self.buf[self.idx..(self.idx+min)];
            let src = &bytes[0..min];
            dst.copy_from_slice(src);
            self.idx += min;
            if self.idx == SHA512_BLOCK_SIZE {
                self.sha512_update(None);
                self.idx = 0;
            }

            bytes = &bytes[min..];
        }

        if bytes.len() > SHA512_BLOCK_SIZE {
            let n = bytes.len() & (!(SHA512_BLOCK_SIZE - 1));
            let data_block = &bytes[0..n];
            self.sha512_update(Some(data_block));
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
            let mut tmp = [0u8; SHA512_BLOCK_SIZE];
            tmp[0] = 0x80;
            let len = self.len;
            if len % SHA512_BLOCK_SIZE < 112 {
                self.write(&tmp[0..(112-(len%SHA512_BLOCK_SIZE))]);
            } else {
                self.write(&tmp[0..(128+112-(len%SHA512_BLOCK_SIZE))]);
            }

            let len = (len as u128) << 3;
            let len_bytes = len.to_be_bytes();
            self.write(&len_bytes[..]);
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
pub struct SHA384 {
    sha_: SHA512,
}

impl SHA384 {
    pub fn new() -> SHA384 {
        Self {
            sha_: SHA512 {
                digest: SHA512_384INIT,
                buf: [0u8; SHA512_BLOCK_SIZE],
                idx: 0,
                len: 0,
                is_checked: false,
            }
        }
    }
}

/// SHA512/256
#[derive(Clone)]
pub struct SHA512T256 {
    sha_: SHA512,
}

impl SHA512T256 {
    pub fn new() -> SHA512T256 {
        Self {
            sha_: SHA512 {
                digest: SHA512_256INIT,
                buf: [0u8; SHA512_BLOCK_SIZE],
                idx: 0,
                len: 0,
                is_checked: false,
            }
        }
    }
}

/// SHA512/224
#[derive(Clone)]
pub struct SHA512T224 {
    sha_: SHA512,
}

impl SHA512T224 {
    pub fn new() -> SHA512T224 {
        Self {
            sha_: SHA512 {
                digest: SHA512_224INIT,
                buf: [0u8; SHA512_BLOCK_SIZE],
                idx: 0,
                len: 0,
                is_checked: false,
            }
        }
    }
}

macro_rules! impl_digest_for_sha512_series {
    ($S: ident, $L: ident) => {
        impl Digest for $S {
            fn bits_len(&self) -> usize {
                $L << 3
            }
        
            fn write(&mut self, data: &[u8]) {
                self.sha_.write(data);
            }
        
            fn checksum(&mut self, digest: &mut Vec<u8>) {
                self.sha_.checksum(digest);
                digest.truncate($L);
            }
        
            fn reset(&mut self) {
                *self = Self::new();
            }
        }
    };
}

impl_digest_for_sha512_series!(SHA384, SHA512T384_DIGEST_SIZE);
impl_digest_for_sha512_series!(SHA512T256, SHA512T256_DIGEST_SIZE);
impl_digest_for_sha512_series!(SHA512T224, SHA512T224_DIGEST_SIZE);

/// SHA512/t
#[derive(Clone)]
pub struct SHA512T {
    sha_: SHA512,
    bits_len: usize,
}

impl SHA512T {
    pub fn new(bits_len: usize) -> Option<SHA512T> {
        if bits_len <= 512 {
            let mut sha_ = SHA512::new();
            sha_.digest.iter_mut().for_each(|e| {
                *e = *e ^ 0xa5a5a5a5a5a5a5a5u64;
            });
            let s = format!("SHA-512/{}", bits_len);
            sha_.write(s.as_bytes());
            let mut _x = Vec::new();
            sha_.checksum(&mut _x);
            sha_.is_checked = false;
            Some(
                SHA512T {
                    sha_,
                    bits_len,
                }
            )
        } else {
            None
        }
    }
}

impl Digest for SHA512T {
    fn bits_len(&self) -> usize {
        self.bits_len
    }

    fn write(&mut self, data: &[u8]) {
        self.sha_.write(data);
    }

    fn checksum(&mut self, digest: &mut Vec<u8>) {
        self.sha_.checksum(digest);
        let (num, rom) = ((self.bits_len + 7) >> 3, self.bits_len & 0x7);
        digest.truncate(num);
        match digest.pop() { 
            Some(x) => {
                let y = if rom > 0 {
                    (x >> (8 - rom)) << rom
                } else {
                    x
                };
                digest.push(y)
            },
            None => {},
        }
    }

    fn reset(&mut self) {
        *self = Self::new(self.bits_len).unwrap()
    }
}