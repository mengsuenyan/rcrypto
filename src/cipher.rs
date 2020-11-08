//! A trait for cryptography

use crate::crypto_err::CryptoError;

/// A trait for cryptography algorithms
pub trait Cipher {
    type Output;
    /// The cryptography algorithm used data block size(in bytes) for plaintext, `None` means that there is
    /// no requirement for the data block size.
    fn block_size(&self) -> Option<usize>;
    
    /// To encrypt the `data_block` and output the encrypted data `dst`, the length in bytes of
    /// the encrypted data will return if encrypt success, otherwise `CryptoError` returned.
    fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<Self::Output, CryptoError>;
    
    /// To decrypt the `cipher_block` and output the decrypted data `dst`, the length in bytes of
    /// the decrypted data will return if decrypt success, other `CryptoError` returned.
    fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<Self::Output, CryptoError>;
}

/// A trait for message digest algorithm used in the cryptography
pub trait Digest {
    
    /// used for HMAC, `None` means that the digest algorithm doesn't support used in the HMAC.
    fn block_size(&self) -> Option<usize>;
    
    /// the digest length(in bits)
    fn bits_len(&self) -> usize;
    
    /// write byte data to the Digester
    fn write(&mut self, data: &[u8]);
    
    /// compute the checksum for all data in the digester, the checksum will be same  
    /// if no new data write to the digester 
    fn checksum(&mut self, digest: &mut Vec<u8>);
    
    /// reset internal state of the Digester to the init state
    fn reset(&mut self);
}

/// Extendable-output functions(XOFs)
pub trait DigestXOF: Digest {
    fn set_digest_len(&mut self, bits_len: usize);
}

/// A trait for signature algorithms
pub trait Signature {
    type Output;
    
    fn sign(&mut self, signature: &mut Vec<u8>, message: &[u8]) -> Result<Self::Output, CryptoError>;
    
    fn verify(&mut self, message: &mut Vec<u8>, signature: &[u8]) -> Result<Self::Output, CryptoError>;
}