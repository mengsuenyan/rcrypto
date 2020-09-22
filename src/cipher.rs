//! A trait for cryptography

use crate::crypto_err::CryptoError;

/// A trait for cryptography algorithms
pub trait Cipher {
    /// The cryptography algorithm used data block size(in bytes) for plaintext, `None` means that there is
    /// no requirement for the data block size.
    fn block_size(&self) -> Option<usize>;
    
    /// To encrypt the `data_block` and output the encrypted data `dst`, the length in bytes of
    /// the encrypted data will return if encrypt success, otherwise `CryptoError` returned.
    fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<usize, CryptoError>;
    
    /// To decrypt the `cipher_block` and output the decrypted data `dst`, the length in bytes of
    /// the decrypted data will return if decrypt success, other `CryptoError` returned.
    fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<usize, CryptoError>;
}

/// A trait for message digest algorithm used in the cryptography
pub trait Digest {
    /// block size in bytes
    fn block_size(&self) -> Option<usize>;
    
    /// write data to the Digester
    fn write(&mut self, data: &[u8]);
    
    /// finished the digest and output to the `digest`
    fn finish(&mut self, digest: &mut Vec<u8>);
    
    /// reset internal state of the Digester to the init state
    fn reset(&mut self);
}