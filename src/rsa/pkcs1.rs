//! [PKCS #1 v2.2](https://www.cnblogs.com/mengsuenyan/p/13796306.html#rsassa-pss)
//! 

use crate::{Digest, CryptoErrorKind, CryptoError, MD5, Cipher, Signature};
use crate::rsa::rsa::KeyPair;
use rmath::bigint::BigInt;
use std::any::{TypeId, Any};
use crate::sha::{SHA1, SHA224, SHA384, SHA256, SHA512};
use std::cell::Cell;
use rmath::rand::IterSource;
use crate::rsa::{PublicKey, PrivateKey};

struct PKCS1Inner<H, R> {
    kp: KeyPair,
    // session_key_len: usize,
    rd: R,
    hf: H,
    is_blinding: bool,
}

/// Signature Scheme: RSASSA-PKCS1;  
/// Encrypt Scheme: RSAES-PKCS1;  
pub struct PKCS1<H, R> {
    inner: Cell<PKCS1Inner<H, R>>,
}

impl<H, R> PKCS1Inner<H, R>
    where H: Digest, R: IterSource<u32> {
    fn new(digest: H, rd: R, key_pair: KeyPair, is_enable_blinding: bool) -> Result<Self, CryptoError> {
        Ok(
            Self {
                kp: key_pair,
                rd,
                hf: digest,
                is_blinding: is_enable_blinding,
            }
        )
    }
    
    fn encrypt(&mut self, cipher: &mut Vec<u8>, msg: &[u8]) -> Result<(), CryptoError> {
        cipher.clear();
        if msg.is_empty() {
            return Ok(());
        }
        
        self.kp.public_key().is_valid()?;
        
        let k = self.kp.modulus_len();
        if msg.len() > k.saturating_sub(11) {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "The msg length is too long"));
        }
        
        let em = cipher;
        let ps_len = k - msg.len() - 3;
        let bound = ps_len + 2;
        em.push(0u8);
        em.push(0x02);
        for e in self.rd.iter_mut() {
            for &x in e.to_be_bytes().iter() {
                if x != 0 {
                    em.push(x);
                }
            }
            
            if em.len() > bound {
                break;
            }
        }
        em.truncate(bound);
        em.push(0x00);
        em.extend(msg.iter());
        
        let m = BigInt::from_be_bytes(em.as_slice());
        let c = self.kp.public_key().encrypt(&m);
        
        let cc = c.to_be_bytes();
        em.clear();
        em.resize(k.saturating_sub(cc.len()), 0);
        em.extend(cc.iter());
        Ok(())
    }
    
    fn decrypt(&mut self, msg: &mut Vec<u8>, cipher_txt: &[u8]) -> Result<(), CryptoError> {
        let k = self.kp.modulus_len();

        if k <= 11 {
            return Err(CryptoError::new(CryptoErrorKind::InvalidPublicKey, "The length of public key moudulus is too short"));
        }

        if k != cipher_txt.len() {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "Invalid cipher text length"));
        }
        
        let kp = self.kp.private_key().ok_or(CryptoError::new(CryptoErrorKind::InvalidPrivateKey, "RSAES-PKCS1: public key cannot be used for decryption"))?;
        kp.public_key().is_valid()?;
        
        let c = BigInt::from_be_bytes(cipher_txt);
        let m = if self.is_blinding {
            kp.decrypt::<R>(&c, Some(&mut self.rd))
        } else {
            kp.decrypt::<R>(&c, None)
        }?;
        let mut em = m.to_be_bytes();
        let old_len = em.len();
        if k > old_len {
            em.resize(k, 0);
            em.rotate_right(k - old_len);
        } else {
            em.truncate(k);
        };

        if em.len() <= 11 || em[0] != 0x00 || em[1] != 0x02 {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid message encoding format"));
        }
        
        let mut idx = 2usize;
        for &ps in em.iter().skip(2) {
            if ps != 0x00 {
                idx += 1;
            } else {
                break;
            }
        }
        
        if idx == em.len() || (idx < 10) {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid message encoding format"));
        }
        
        idx += 1;
        msg.clear();
        msg.extend(em.iter().skip(idx));
        Ok(())
    }
    
}

impl<H, R> PKCS1Inner<H, R> 
    where H: Digest + Any, R: IterSource<u32> {
    fn sign(&mut self, sign: &mut Vec<u8>, m_hash: &[u8]) -> Result<(), CryptoError> {
        let h_len = (self.hf.bits_len() + 7) >> 3;
        let mut prefix = self.pkcs1_hash_info()?;
        
        let kp = self.kp.private_key().ok_or(CryptoError::new(CryptoErrorKind::InvalidPrivateKey, "RSASSA-PKCS1: public key cannot be used for signing"))?;
        let (t_len, k) = (prefix.len() + h_len, kp.modulus_len());
        if k < (t_len + 11) {
            return Err(CryptoError::new(CryptoErrorKind::InvalidPrivateKey, "The private modulus length is too short"));
        }
        
        // EM = 0x00 || 0x01 || PS || 0x00 || T
        sign.clear();
        sign.push(0x00);
        sign.push(0x01);
        sign.extend(std::iter::repeat(0xff).take(k - t_len - 3));
        sign.push(0x00);
        sign.append(&mut prefix);
        self.hf.reset();
        self.hf.write(m_hash);
        self.hf.checksum(&mut prefix);
        sign.append(&mut prefix);
        
        let m = BigInt::from_be_bytes(sign.as_slice());
        let c = if self.is_blinding {
            kp.decrypt_and_check::<R>(&m, Some(&mut self.rd))
        } else {
            kp.decrypt_and_check::<R>(&m, None)
        }?;
        
        let mut c = c.to_be_bytes();
        let len = k.saturating_sub(c.len());
        sign.clear();
        sign.resize(len, 0);
        sign.append(&mut c);
        Ok(())
    }
    
    fn verify(&mut self, sign: &[u8], m_hash: &[u8]) -> Result<(), CryptoError> {
        let h_len = (self.hf.bits_len() + 7) >> 3;
        let mut prefix = self.pkcs1_hash_info()?;
        
        let (t_len, k) = (prefix.len() + h_len, self.kp.public_key().modulus_len());
        if k < (t_len + 11) {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "The public key modulus length is too short"));
        }
        
        let c = BigInt::from_be_bytes(sign);
        let m = self.kp.public_key().encrypt(&c);
        let mut em = m.to_be_bytes();
        let old_len = em.len();
        if k >  old_len {
            em.resize(k, 0);
            em.rotate_right(k - old_len);
        } else {
            em.truncate(k);
        };
        
        if em[0] != 0x00 || em[1] != 0x01 || &em[(k-t_len)..(k-h_len)] != prefix.as_slice() || em[k-t_len-1] != 0x00 {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid message encoding format"));
        }
        
        self.hf.reset();
        self.hf.write(m_hash);
        let m_hash = &mut prefix;
        self.hf.checksum(m_hash);
        if &em[(k-h_len)..] != m_hash.as_slice() {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid message encoding format"));
        }

        for &e in em.iter().skip(2).take(k-t_len-3) {
            if e != 0xff {
                return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid message encoding format"));
            }
        }
        
        Ok(())
    }

    /// These are ASN1 DER structures:
    ///   DigestInfo ::= SEQUENCE {
    ///     digestAlgorithm AlgorithmIdentifier,
    ///     digest OCTET STRING
    ///   }
    /// For performance, we don't use the generic ASN1 encoder. Rather, we
    /// precompute a prefix of the digest value that makes a valid ASN1 DER string
    /// with the correct contents.
    fn pkcs1_hash_prefix() -> Result<Vec<u8>, CryptoError> {
        if TypeId::of::<H>() == TypeId::of::<MD5>() {
            Ok(vec![0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10])
        } else if TypeId::of::<H>() == TypeId::of::<SHA1>() {
            Ok(vec![0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14])
        } else if TypeId::of::<H>() == TypeId::of::<SHA224>() {
            Ok(vec![0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c])
        } else if TypeId::of::<H>() == TypeId::of::<SHA256>() {
            Ok(vec![0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20])
        } else if TypeId::of::<H>() == TypeId::of::<SHA384>() {
            Ok(vec![0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30])
        } else if TypeId::of::<H>() == TypeId::of::<SHA512>() {
            Ok(vec![0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40])
        } else {
            unreachable!(format!("not suuport {}", std::any::type_name::<H>()));
        }
    }
    
    fn pkcs1_hash_info(&self) -> Result<Vec<u8>, CryptoError> {
        Self::pkcs1_hash_prefix().map(|x| {x})
    }
} 


impl<H, R> PKCS1<H, R>
    where H: Digest + Clone, R: IterSource<u32> {

    pub fn digest_func(&self) -> H {
        let mut h = unsafe {
            (*self.inner.as_ptr()).hf.clone()
        };
        h.reset();
        h
    }
}

impl<H, R> PKCS1<H, R>
    where H: Digest, R: IterSource<u32> + Clone {

    pub fn rand_source(&self) -> R {
        unsafe {
            (*self.inner.as_ptr()).rd.clone()
        }
    }
}

impl<H, R> PKCS1<H, R>
    where H: Digest + Any, R: IterSource<u32> {
    
    fn get_pkcs1inner(&self) -> &PKCS1Inner<H, R> {
        unsafe {
            & (*self.inner.as_ptr())
        }
    }
    
    fn get_pkcs1inner_mut(&self) -> &mut PKCS1Inner<H, R> {
        unsafe {
            &mut (*self.inner.as_ptr())
        }
    }

    /// digest message length in bytes
    pub fn digest_len(&self) -> usize {
        (self.get_pkcs1inner().hf.bits_len() + 7) >> 3
    }

    /// public key length in bytes
    pub fn modulus_len(&self) -> usize {
        self.public_key().modulus_len()
    }

    pub fn public_key(&self) -> &PublicKey {
        self.get_pkcs1inner().kp.public_key()
    }

    /// maximum message length in byte allowed to be encrypted
    pub fn encrypt_max_message_len(&self) -> usize {
        self.modulus_len().saturating_sub(11)
    }
    
    fn check_hash_is_support() -> Result<(), CryptoError> {
        if TypeId::of::<H>() != TypeId::of::<MD5>() {
            Ok(())
        } else if TypeId::of::<H>() != TypeId::of::<SHA1>() {
            Ok(())
        } else if TypeId::of::<H>() != TypeId::of::<SHA224>() {
            Ok(())
        } else if TypeId::of::<H>() != TypeId::of::<SHA256>() {
            Ok(())
        } else if TypeId::of::<H>() != TypeId::of::<SHA384>() {
            Ok(())
        } else if TypeId::of::<H>() != TypeId::of::<SHA512>() {
            Ok(())
        } else {
            Err(CryptoError::new(CryptoErrorKind::NotSupportUsage, format!("{} is not currently supported", std::any::type_name::<H>())))
        }
    }

    /// maximum message length in byte  allowed to be signing
    pub fn sign_max_message_len(&self) -> usize {
        #[cfg(target_pointer_width = "32")]
        {
            u32::MAX as usize
        }
        
        #[cfg(target_pointer_width = "64")]
        {
            u64::MAX as usize
        }
    }
    
    pub fn new_uncheck(digest: H, rd: R, key_pair: KeyPair, is_enable_blinding: bool) -> Result<Self, CryptoError> {
        Self::check_hash_is_support()?;
        
        if key_pair.modulus_len() <= 11 {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "The modulus length is too small"));
        }

        let inner = PKCS1Inner::new(digest, rd, key_pair, is_enable_blinding)?;
        
        Ok(
            Self {
                inner: Cell::new(inner),
            }
        )
    }
    
    pub fn new(digest: H, rd: R, key_pair: KeyPair, is_enable_blinding: bool) -> Result<Self, CryptoError> {
        Self::check_hash_is_support()?;
        
        if key_pair.private_key().is_some() {
            key_pair.private_key().unwrap().is_valid()?;
        } else {
            key_pair.public_key().is_valid()?;
        }
        
        Self::new_uncheck(digest, rd, key_pair, is_enable_blinding)
    }
    
    pub fn auto_generate_key(bits_len: usize, test_round_times: usize, digest: H, mut rd: R, is_enable_blinding: bool) -> Result<Self, CryptoError> {
        Self::check_hash_is_support()?;
        
        let h_len = (digest.bits_len() + 7) >> 3;
        
        if bits_len <= (11 + h_len) {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "The bits_len is too small"));
        }
        
        let key_ = PrivateKey::generate_key(bits_len, test_round_times, &mut rd)?;
        
        Self::new_uncheck(digest, rd, KeyPair::from(key_), is_enable_blinding)
    }
}

impl<H, R> Cipher for PKCS1<H, R>
    where H: Digest + Any, R: IterSource<u32> {
    type Output = ();

    fn block_size(&self) -> Option<usize> {
        None
    }

    /// the length of plaintext should be less than or equal to `self.encrypt_max_message_len()`
    fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<Self::Output, CryptoError> {
        let inner = self.get_pkcs1inner_mut();
        inner.encrypt(dst, plaintext_block)
    }

    /// the length of ciphertex should be equal to `self.modulus_len()`
    fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<Self::Output, CryptoError> {
        let inner = self.get_pkcs1inner_mut();
        inner.decrypt(dst, cipher_block)
    }
}

impl<H, R> Signature for PKCS1<H, R>
    where H: Digest + Any, R: IterSource<u32> {
    type Output = ();

    /// the length of message should be less than or equal to `self.sign_max_message_len()`
    fn sign(&mut self, signature: &mut Vec<u8>, message: &[u8]) -> Result<Self::Output, CryptoError> {
        self.inner.get_mut().sign(signature, message)
    }

    /// the length of signature should be equal to `self.modulus_len()`
    fn verify(&mut self, signature: &[u8], message: &[u8]) -> Result<Self::Output, CryptoError> {
        self.inner.get_mut().verify(signature, message)
    }
}