//! [KECCAK](keccak.noekeon.org)  
//! 
//! SHA-3: FIPS-202  
//! 
//! https://www.cnblogs.com/mengsuenyan/p/13182759.html  
//! 
//! KECCAK[c] = SPONGE[KECCAK-p[1600, 24], pad10*1, 1600-c];   
//! KECCAK[c](N, d) = SPONGE[KECCAK-p[1600, 24], pad10*1, 1600-c](N, d);   
//! 
//! SHAKE128(M,d) = KECCAK[256](M||1111,d)
//! SHAKE256(M,d) = KECCAK[512](M||1111,d)

use crate::{KeccakSponge, Digest, Keccak, DigestXOF};

macro_rules! impl_shake {
    ($Type0: ident, $SUFFIX: literal, $SUFFIX_LEN: literal, $BITS_LEN: literal) => {
        #[derive(Clone)]
        pub struct $Type0{
            digest: Vec<u8>,
            sponge: KeccakSponge,
            want_bits_len: usize,
            suffix: [u8;1],
            suffix_len: usize,
            is_checked: bool,
        }
        
        impl $Type0 {
            pub fn new(digest_bits_len: usize) -> Self {
                Self {
                    sponge: Keccak::new(1600, 24).unwrap().sponge(1600-($BITS_LEN << 1)).unwrap(),
                    digest: Vec::with_capacity(64),
                    want_bits_len: digest_bits_len,
                    suffix: [$SUFFIX << (7 - $SUFFIX_LEN)],
                    suffix_len: $SUFFIX_LEN,
                    is_checked: false,
                }
            }
            
            pub fn is_raw_shake(&self) -> bool {
                self.suffix == [0b11u8 << 5]
            }
            
            pub fn to_raw_shake(self) -> Self {
                let mut tmp = self;
                tmp.suffix = [0b11u8 << 5];
                tmp.suffix_len = 2;
                tmp
            }
        }
        
        impl Digest for $Type0 {
            fn block_size(&self) -> Option<usize> {
                None
            }
        
            fn bits_len(&self) -> usize {
                self.want_bits_len
            }
        
            fn write(&mut self, data: &[u8]) {
                self.sponge.write_to_buf(data, data.len() << 3);
                
                self.is_checked = false;
            }
        
            fn checksum(&mut self, digest: &mut Vec<u8>) {
                if !self.is_checked {
                    self.sponge.write_to_buf(self.suffix.as_ref(), self.suffix_len);
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
        
        impl DigestXOF for $Type0 {
            fn set_digest_len(&mut self, bits_len: usize) {
                self.want_bits_len = bits_len;
                self.reset();
            }
        }
    };
}

impl_shake!(Shake128, 0b1111, 4, 128);
impl_shake!(Shake256, 0b1111, 4, 256);
