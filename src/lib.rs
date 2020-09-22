
extern crate rmath;

mod cipher;
pub use cipher::Cipher;

mod crypto_err;
pub use crypto_err::{CryptoErrorKind, CryptoError};

mod aes;
pub use aes::AES;

mod des;
pub use des::DES;