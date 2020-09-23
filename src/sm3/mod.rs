//! SM3 Cryptographic Hash Algorithm  
//! 
//! https://www.cnblogs.com/mengsuenyan/p/13183543.html  
//! 
//! # Examples
//! 
//! ```Rust
//! use rcrypto::{SM3, Digest};
//! 
//! let cases = [
//!     ("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", "abc"),
//!     ("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732","abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"),
//! ];
//! 
//! let mut sm3 = SM3::new();
//! let mut digest = Vec::new();
//! 
//! cases.iter().for_each(|&e| {
//!     sm3.write(e.1.as_bytes());
//!     sm3.checksum(&mut digest);
//!     assert_eq!(e.0, cvt_bytes_to_str(digest.as_slice()), "case: {}", e.1);
//!     sm3.checksum(&mut digest);
//!     assert_eq!(e.0, cvt_bytes_to_str(digest.as_slice()), "case: {}", e.1);
//!     sm3.reset();
//! });
//! ```

mod sm3;
pub use sm3::SM3;