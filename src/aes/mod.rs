//! AES(Advanced Encryption Standard)  
//! FIPS 197  
//! https://www.cnblogs.com/mengsuenyan/p/12697694.html  
//! 
//! # Example
//! 
//! ```Rust
//! use rcrypto::{AES, Cipher};
//! 
//! let cipher = AES::aes_192([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
//! 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,]);
//! 
//! cipher.encrypt(&mut dst0, vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff].as_slice()).unwrap();
//! cipher.decrypt(&mut dst1, vec![0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91].as_slice()).unwrap();
//! ```

#[cfg(not(all(rcrypto_aes = "support", any(target_arch = "x86", target_arch = "x86_64"))))]
mod const_tables;

#[cfg(not(all(rcrypto_aes = "support", any(target_arch = "x86", target_arch = "x86_64"))))]
mod aes_generic;
#[cfg(not(all(rcrypto_aes = "support", any(target_arch = "x86", target_arch = "x86_64"))))]
pub use aes_generic::AES;


#[cfg(all(rcrypto_aes = "support", any(target_arch = "x86", target_arch = "x86_64")))]
mod aes_amd64;
#[cfg(all(rcrypto_aes = "support", any(target_arch = "x86", target_arch = "x86_64")))]
pub use aes_amd64::AES;

mod aes;

