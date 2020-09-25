//! [KECCAK](keccak.noekeon.org)  
//! 
//! SHA-3: FIPS-202  
//! 
//! https://www.cnblogs.com/mengsuenyan/p/13182759.html  
//! 
//! KECCAK[c] = SPONGE[KECCAK-p[1600, 24], pad10*1, 1600-c];   
//! KECCAK[c](N, d) = SPONGE[KECCAK-p[1600, 24], pad10*1, 1600-c](N, d);   
//! 
//! SHA3-224(M) = KECCAK[448](M||01,224)
//! SHA3-256(M) = KECCAK[512](M||01,256)
//! SHA3-384(M) = KECCAK[768](M||01,384)
//! SHA3-512(M) = KECCAK[1024](M||01,512)


use crate::{KeccakSponge, Digest, Keccak};

enum SHA3Type {
    SHA224(SHA224),
    SHA256(SHA256),
    SHA384(SHA384),
    SHA512(SHA512),
}

pub struct SHA3 {
    sha_: SHA3Type,
}

impl SHA3 {
    
    pub fn sha224() -> Self {
        Self {
            sha_: SHA3Type::SHA224(SHA224::new())
        }
    }

    pub fn sha256() -> Self {
        Self {
            sha_: SHA3Type::SHA256(SHA256::new())
        }
    }

    pub fn sha384() -> Self {
        Self {
            sha_: SHA3Type::SHA384(SHA384::new())
        }
    }

    pub fn sha512() -> Self {
        Self {
            sha_: SHA3Type::SHA512(SHA512::new())
        }
    }
}

impl Digest for SHA3 {
    fn block_size(&self) -> Option<usize> {
        match &self.sha_ {
            SHA3Type::SHA224(x) => x.block_size(),
            SHA3Type::SHA256(x) => x.block_size(),
            SHA3Type::SHA384(x) => x.block_size(),
            SHA3Type::SHA512(x) => x.block_size(),
        }
    }

    fn bits_len(&self) -> usize {
        match &self.sha_ {
            SHA3Type::SHA224(x) => x.bits_len(),
            SHA3Type::SHA256(x) => x.bits_len(),
            SHA3Type::SHA384(x) => x.bits_len(),
            SHA3Type::SHA512(x) => x.bits_len(),
        }
    }

    fn write(&mut self, data: &[u8]) {
        match &mut self.sha_ {
            SHA3Type::SHA224(x) => x.write(data),
            SHA3Type::SHA256(x) => x.write(data),
            SHA3Type::SHA384(x) => x.write(data),
            SHA3Type::SHA512(x) => x.write(data),
        }
    }

    fn checksum(&mut self, digest: &mut Vec<u8>) {
        match &mut self.sha_ {
            SHA3Type::SHA224(x) => x.checksum(digest),
            SHA3Type::SHA256(x) => x.checksum(digest),
                SHA3Type::SHA384(x) => x.checksum(digest),
            SHA3Type::SHA512(x) => x.checksum(digest),
        }
    }

    fn reset(&mut self) {
        match &mut self.sha_ {
            SHA3Type::SHA224(x) => x.reset(),
            SHA3Type::SHA256(x) => x.reset(),
                SHA3Type::SHA384(x) => x.reset(),
            SHA3Type::SHA512(x) => x.reset(),
        }
    }
}

macro_rules! impl_sha3sub {
    ($Type0: ident, $SUFFIX: literal, $SUFFIX_LEN: literal, $BITS_LEN: literal) => {
        #[derive(Clone)]
        pub struct $Type0{
            digest: Vec<u8>,
            sponge: KeccakSponge,
            is_checked: bool,
        }
        
        impl $Type0 {
            pub fn new() -> Self {
                Self {
                    sponge: Keccak::new(1600, 24).unwrap().sponge(1600-($BITS_LEN << 1)).unwrap(),
                    digest: Vec::with_capacity(64),
                    is_checked: false,
                }
            }
        }
        
        impl Digest for $Type0 {
            fn block_size(&self) -> Option<usize> {
                Some((1600 - ($BITS_LEN << 1)) >> 3)
            }
        
            fn bits_len(&self) -> usize {
                $BITS_LEN
            }
        
            fn write(&mut self, data: &[u8]) {
                self.sponge.write_to_buf(data, data.len() << 3);
                
                self.is_checked = false;
            }
        
            fn checksum(&mut self, digest: &mut Vec<u8>) {
                if !self.is_checked {
                    const SUFFIX_BITS_LEN: usize = $SUFFIX_LEN;
                    const SUFFIX: [u8;1] = [$SUFFIX << (7 - SUFFIX_BITS_LEN)];
                    self.sponge.write_to_buf(&SUFFIX, SUFFIX_BITS_LEN);
                    self.sponge.sponge_buf(self.bits_len(), &mut self.digest);
                    
                    self.sponge.clear_buf();
                    self.is_checked = true;
                }
                
                digest.clear();
                digest.extend(self.digest.iter());
            }
        
            fn reset(&mut self) {
                self.sponge.clear_buf();
                self.digest.clear();
                self.is_checked = false;
            }
        }
    };
}

impl_sha3sub!(SHA224, 0b01, 2, 224);
impl_sha3sub!(SHA256, 0b01, 2, 256);
impl_sha3sub!(SHA384, 0b01, 2, 384);
impl_sha3sub!(SHA512, 0b01, 2, 512);
        