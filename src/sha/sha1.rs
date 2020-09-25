//! SHA-1  
//! https://www.cnblogs.com/mengsuenyan/p/12697811.html#toc  

use crate::sha::const_tables::{SHA1_DIGEST_WSIZE, SHA1_BLOCK_SIZE, SHA1_INIT, SHA1_DIGEST_SIZE};
use crate::Digest;

#[derive(Clone)]
pub struct SHA1 {
    pub(super) digest: [u32; SHA1_DIGEST_WSIZE],
    pub(super) buf: [u8; SHA1_BLOCK_SIZE],
    pub(super) idx: usize,
    pub(super) len: usize,
    pub(super) is_checked: bool,
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
}

impl Digest for SHA1 {
    fn block_size(&self) -> Option<usize> {
        Some(64)
    }

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
