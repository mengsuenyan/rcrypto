//! SHA-256/SHA-224  
//! https://www.cnblogs.com/mengsuenyan/p/12697811.html#toc  

use crate::sha::const_tables::{SHA256_DIGEST_WSIZE, SHA256_BLOCK_SIZE, SHA256_INIT, SHA256_DIGEST_SIZE, SHA224_INIT, SHA224_BLOCK_SIZE, SHA224_DIGEST_SIZE};
use crate::Digest;

#[derive(Clone)]
pub struct SHA256 {
    pub(super) digest: [u32; SHA256_DIGEST_WSIZE],
    pub(super) buf: [u8; SHA256_BLOCK_SIZE],
    pub(super) idx: usize,
    pub(super) len: usize,
    pub(super) is_checked: bool,
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
}

impl Digest for SHA256 {
    fn block_size(&self) -> Option<usize> {
        Some(64)
    }

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
    fn block_size(&self) -> Option<usize> {
        Some(64)
    }

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
