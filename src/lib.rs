
extern crate rmath;

mod cipher;
pub use cipher::{Cipher, Digest};

mod crypto_err;
pub use crypto_err::{CryptoErrorKind, CryptoError};

mod aes;
pub use aes::AES;

mod des;
pub use des::DES;

mod md5;
pub use md5::MD5;

pub mod sha;
pub use sha::SHA;
