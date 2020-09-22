pub use crate::sha::generic::{SHA1, SHA256, SHA224, SHA384, SHA512, SHA512T224, SHA512T256, SHA512T};
use crate::Digest;

#[derive(Clone)]
enum SHAType {
    SHA1(SHA1),
    SHA256(SHA256),
    SHA224(SHA224),
    SHA384(SHA384),
    SHA512(SHA512),
    SHA512T224(SHA512T224),
    SHA512T256(SHA512T256),
    SHA512T(SHA512T),
}

#[derive(Clone)]
pub struct SHA {
    sha_: SHAType,
}

impl SHA {
    pub fn sha1() -> Self {
        Self {
            sha_: SHAType::SHA1(SHA1::new())
        }
    }
    
    pub fn sha256() -> Self {
        Self {
            sha_: SHAType::SHA256(SHA256::new())
        }
    }

    pub fn sha224() -> Self {
        Self {
            sha_: SHAType::SHA224(SHA224::new())
        }
    }

    pub fn sha384() -> Self {
        Self {
            sha_: SHAType::SHA384(SHA384::new())
        }
    }

    pub fn sha512() -> Self {
        Self {
            sha_: SHAType::SHA512(SHA512::new())
        }
    }

    pub fn sha512t(bits_len: usize) -> Option<Self> {
        if bits_len <= 512 {
            Some(Self {
                sha_: SHAType::SHA512T(SHA512T::new(bits_len).unwrap())
            })
        } else {
            None
        }
    }
    
    /// SHA512/256
    pub fn sha512_256() -> Self {
        Self {
            sha_: SHAType::SHA512T256(SHA512T256::new())
        }
    }

    /// SHA512/224
    pub fn sha512_224() -> Self {
        Self {
            sha_: SHAType::SHA512T224(SHA512T224::new())
        }
    }
}

impl Digest for SHA {
    fn bits_len(&self) -> usize {
        match &self.sha_ {
            SHAType::SHA1(x) => x.bits_len(),
            SHAType::SHA224(x) => x.bits_len(),
            SHAType::SHA256(x) => x.bits_len(),
            SHAType::SHA384(x) => x.bits_len(),
            SHAType::SHA512(x) => x.bits_len(),
            SHAType::SHA512T224(x) => x.bits_len(),
            SHAType::SHA512T256(x) => x.bits_len(),
            SHAType::SHA512T(x) => x.bits_len(),
        }
    }

    fn write(&mut self, data: &[u8]) {
        match &mut self.sha_ {
            SHAType::SHA1(x) => x.write(data),
            SHAType::SHA224(x) => x.write(data),
            SHAType::SHA256(x) => x.write(data),
            SHAType::SHA384(x) => x.write(data),
            SHAType::SHA512(x) => x.write(data),
            SHAType::SHA512T224(x) => x.write(data),
            SHAType::SHA512T256(x) => x.write(data),
            SHAType::SHA512T(x) => x.write(data),
        }
    }

    fn checksum(&mut self, digest: &mut Vec<u8>) {
        match &mut self.sha_ {
            SHAType::SHA1(x) => x.checksum(digest),
            SHAType::SHA224(x) => x.checksum(digest),
            SHAType::SHA256(x) => x.checksum(digest),
            SHAType::SHA384(x) => x.checksum(digest),
            SHAType::SHA512(x) => x.checksum(digest),
            SHAType::SHA512T224(x) => x.checksum(digest),
            SHAType::SHA512T256(x) => x.checksum(digest),
            SHAType::SHA512T(x) => x.checksum(digest),
        }
    }

    fn reset(&mut self) {
        match &mut self.sha_ {
            SHAType::SHA1(x) => x.reset(),
            SHAType::SHA224(x) => x.reset(),
            SHAType::SHA256(x) => x.reset(),
            SHAType::SHA384(x) => x.reset(),
            SHAType::SHA512(x) => x.reset(),
            SHAType::SHA512T224(x) => x.reset(),
            SHAType::SHA512T256(x) => x.reset(),
            SHAType::SHA512T(x) => x.reset(),
        }
    }
}

#[cfg(test)]
mod tests;