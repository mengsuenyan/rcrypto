//! DES(Data Encryption Standard)  
//! FIPS 46-3  
//! https://www.cnblogs.com/mengsuenyan/p/12905365.html   
//! 
//! # Example
//! 
//! ```Rust
//! use rcrypto::{DES, Cipher};
//! 
//! let cases = [
//!     ([0x6e, 0x5e, 0xe2, 0x47, 0xc4, 0xbf, 0xf6, 0x51], // random
//!     [0x11, 0xc9, 0x57, 0xff, 0x66, 0x89, 0x0e, 0xf0], // random
//!     [0x94, 0xc5, 0x35, 0xb2, 0xc5, 0x8b, 0x39, 0x72]),
//! ];
//! 
//! for ele in cases.iter() {
//!     let cipher = DES::new(ele.0);
//!     let (mut encrypt, mut decrypt) = (Vec::with_capacity(8), Vec::with_capacity(8));
//!     cipher.encrypt(&mut encrypt, ele.1.as_ref()).unwrap();
//!     cipher.decrypt(&mut decrypt, encrypt.as_slice()).unwrap();
//! }
//! ```


mod des;
mod const_tables;
mod tdes;

pub use des::DES;
pub use tdes::TDES;
