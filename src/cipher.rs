//! A trait for cryptography

use crate::crypto_err::CryptoError;

pub trait Cipher {
    /// The cryptography algorithm used data block size for plaintext, `None` means that there is
    /// no requirement for the data block size.
    fn block_size(&self) -> Option<usize>;
    
    /// To encrypt the `data_block` and output the encrypted data `dst`, the length in bytes of
    /// the encrypted data will return if encrypt success, otherwise `CryptoError` returned.
    fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<usize, CryptoError>;
    
    /// To decrypt the `cipher_data` and output the decrypted data `dst`, the length in bytes of
    /// the decrypted data will return if decrypt success, other `CryptoError` returned.
    fn decrypt(&self, dst: &mut Vec<u8>, cipher_data: &[u8]) -> Result<usize, CryptoError>;
}