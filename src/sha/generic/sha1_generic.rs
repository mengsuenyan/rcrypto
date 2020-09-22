//! SHA-1  
//! https://www.cnblogs.com/mengsuenyan/p/12697811.html#toc  

use crate::sha::generic::const_tables::{SHA1_DIGEST_WSIZE, SHA1_BLOCK_SIZE, SHA1_INIT, SHA1_WORD_LEN, SHA1_K, f_ch, f_parity, f_maj, SHA1_DIGEST_SIZE};
use crate::Digest;

#[derive(Clone)]
pub struct SHA1 {
    digest: [u32; SHA1_DIGEST_WSIZE],
    buf: [u8; SHA1_BLOCK_SIZE],
    idx: usize,
    len: usize,
    is_checked: bool,
}

macro_rules! sha1_upd_digest {
    ($a: ident, $b: ident, $c: ident, $d: ident, $e: ident, $A: ident, $B: ident, $C: ident, $D: ident, $E: ident) => {
        {
            let (aa, bb, cc, dd, ee) = ($A, $B, $C, $D, $E);
            $a = aa;
            $b = bb;
            $c = cc;
            $d = dd;
            $e = ee;
        };
    };
}

impl SHA1 {
    pub fn new() -> SHA1 {
        SHA1 {
            digest: SHA1_INIT,
            buf: [0u8; SHA1_BLOCK_SIZE],
            idx: 0,
            len: 0,
            is_checked: false,
        }
    }

    #[inline]
    fn f_word_extract(w: &mut [u32; SHA1_BLOCK_SIZE/SHA1_WORD_LEN], s: usize) -> u32 {
        w[s&0xf] = (w[(s+13)&0xf] ^ w[(s+8)&0xf] ^ w[(s+2)&0xf] ^ w[s&0xf]).rotate_left(1);
        // w[s&0xf] = (w[(s-3)&0xf] ^ w[(s-8)&0xf] ^ w[(s-14)&0xf] ^ w[(s-16)&0xf]).rotate_left(1);
        w[s&0xf]
    }

    fn update(&mut self, data_block: Option<&[u8]>) {
        let data_block = match data_block {
            Some(x) => x,
            None => self.buf.as_ref(),
        };
        
        let mut chunk = 0;

        let (mut h0, mut h1, mut h2, mut h3, mut h4) = (self.digest[0], self.digest[1], self.digest[2], self.digest[3], self.digest[4]);
        while chunk < data_block.len() {
            let bytes = &data_block[chunk..(chunk+SHA1_BLOCK_SIZE)];

            const LEN: usize = SHA1_BLOCK_SIZE / SHA1_WORD_LEN;
            let mut word = [0u32; LEN];
            let mut bytes_itr = bytes.iter();
            for i in 0..LEN {
                let v = [*bytes_itr.next().unwrap(), *bytes_itr.next().unwrap(), *bytes_itr.next().unwrap(), *bytes_itr.next().unwrap()];
                word[i] = u32::from_be_bytes(v);
            }

            let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

            let mut j = 0;
            while j < 16 {
                let t = a.rotate_left(5).wrapping_add(f_ch(b, c, d)).wrapping_add(e).wrapping_add(SHA1_K[0]).wrapping_add(word[j]);
                let b_p = b.rotate_left(30);
                sha1_upd_digest!(a, b, c, d, e, t, a, b_p, c, d);
                j += 1;
            }

            while j < 20 {
                let t = a.rotate_left(5).wrapping_add(f_ch(b, c, d)).wrapping_add(e).wrapping_add(SHA1_K[0]).wrapping_add(SHA1::f_word_extract(&mut word, j));
                let b_p = b.rotate_left(30);
                sha1_upd_digest!(a, b, c, d, e, t, a, b_p, c, d);
                j += 1;
            }

            while j < 40 {
                let t = a.rotate_left(5).wrapping_add(f_parity(b, c, d)).wrapping_add(e).wrapping_add(SHA1_K[1]).wrapping_add(SHA1::f_word_extract(&mut word, j));
                let b_p = b.rotate_left(30);
                sha1_upd_digest!(a, b, c, d, e, t, a, b_p, c, d);
                j += 1;
            }

            while j < 60 {
                let t = a.rotate_left(5).wrapping_add(f_maj(b, c, d)).wrapping_add(e).wrapping_add(SHA1_K[2]).wrapping_add(SHA1::f_word_extract(&mut word, j));
                let b_p = b.rotate_left(30);
                sha1_upd_digest!(a, b, c, d, e, t, a, b_p, c, d);
                j += 1;
            }

            while j < 80 {
                let t = a.rotate_left(5).wrapping_add(f_parity(b, c, d)).wrapping_add(e).wrapping_add(SHA1_K[3]).wrapping_add(SHA1::f_word_extract(&mut word, j));
                let b_p = b.rotate_left(30);
                sha1_upd_digest!(a, b, c, d, e, t, a, b_p, c, d);
                j += 1;
            }

            h0 = h0.wrapping_add(a);
            h1 = h1.wrapping_add(b);
            h2 = h2.wrapping_add(c);
            h3 = h3.wrapping_add(d);
            h4 = h4.wrapping_add(e);
            chunk += SHA1_BLOCK_SIZE;
        }

        self.digest[0] = h0;
        self.digest[1] = h1;
        self.digest[2] = h2;
        self.digest[3] = h3;
        self.digest[4] = h4;
    }
}

impl Digest for SHA1 {
    fn bits_len(&self) -> usize {
        SHA1_DIGEST_SIZE << 3
    }

    fn write(&mut self, data: &[u8]) {
        let mut data = data;
        self.len += data.len();

        if self.idx > 0 {
            let min = std::cmp::min(SHA1_BLOCK_SIZE - self.idx, data.len());
            let dst = &mut self.buf[self.idx..(self.idx+min)];
            let src = &data[0..min];
            dst.copy_from_slice(src);
            self.idx += min;

            if self.idx == SHA1_BLOCK_SIZE {
                self.update(None);
                self.idx = 0;
            }

            data = &data[min..];
        }

        if data.len() > SHA1_BLOCK_SIZE {
            let n = data.len() & (!(SHA1_BLOCK_SIZE - 1));
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
            let mut tmp = [0u8; SHA1_BLOCK_SIZE];
            tmp[0] = 0x80;
            let len = self.len;
            if len % SHA1_BLOCK_SIZE < 56 {
                self.write(&tmp[0..(56-(len%SHA1_BLOCK_SIZE))]);
            } else {
                self.write(&tmp[0..(64+56-(len%SHA1_BLOCK_SIZE))]);
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
        *self = SHA1::new();
    }
}