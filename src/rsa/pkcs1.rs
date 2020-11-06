//! [PKCS #1 v2.2](https://www.cnblogs.com/mengsuenyan/p/13796306.html#rsassa-pss)
//! 

use crate::{Digest, CryptoErrorKind, CryptoError, MD5};
use crate::rsa::rsa::KeyPair;
use rmath::bigint::BigInt;
use std::any::{TypeId, Any};
use crate::sha::{SHA1, SHA224, SHA384, SHA256, SHA512};

/// Signature Scheme: RSASSA-PKCS1;  
/// Encrypt Scheme: RSAES-PKCS1;  
pub struct PKCS1<H, R> {
    kp: KeyPair,
    // session_key_len: usize,
    rd: R,
    hf: H,
    is_blinding: bool,
}

impl<H, R> PKCS1<H, R>
    where H: Digest, R: rmath::rand::IterSource<u32> {
    pub fn new(digestor: H, rd: R, key_pair: KeyPair, is_enable_blinding: bool) -> Result<Self, CryptoError> {
        Ok(
            Self {
                kp: key_pair,
                rd,
                hf: digestor,
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
        
        let k = self.kp.modulus_size();
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
        let k = self.kp.modulus_size();
        
        if k != cipher_txt.len() {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "Invalid cipher text length"));
        }
        
        self.kp.public_key().is_valid()?;
        
        if k < 11 {
            return Err(CryptoError::new(CryptoErrorKind::InvalidPublicKey, "The length of public key moudulus is too short"));
        }
        
        let c = BigInt::from_be_bytes(cipher_txt);
        let m = if self.is_blinding {
            self.kp.decrypt::<R>(&c, Some(&mut self.rd))
        } else {
            self.kp.decrypt::<R>(&c, None)
        }?;
        let mut em = m.to_be_bytes();
        let old_len = em.len();
        if k > old_len {
            em.resize(k, 0);
            em.rotate_right(k - old_len);
        } else {
            em.truncate(k);
        };
        
        if em.len() < 11 || em[0] != 0x00 || em[2] != 0x02 {
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

impl<H, R> PKCS1<H, R> 
    where H: Digest + Any, R: rmath::rand::IterSource<u32> {
    fn sign(&mut self, sign: &mut Vec<u8>, m_hash: &[u8]) -> Result<(), CryptoError> {
        let (mut prefix, h_len) = self.pkcs1_hash_info(m_hash.len())?;
        
        let (t_len, k) = (prefix.len() + h_len, self.kp.modulus_size());
        if k < (t_len + 11) {
            return Err(CryptoError::new(CryptoErrorKind::InvalidPrivateKey, "The private modulus length is too short"));
        }
        
        sign.clear();
        sign.push(0x00);
        sign.push(0x01);
        sign.extend(std::iter::repeat(0xff).take(k - t_len - 3));
        sign.append(&mut prefix);
        sign.extend(m_hash.iter());
        
        let m = BigInt::from_be_bytes(sign.as_slice());
        let c = if self.is_blinding {
            self.kp.decrypt_and_check::<R>(&m, Some(&mut self.rd))
        } else {
            self.kp.decrypt_and_check::<R>(&m, None)
        }?;
        
        let mut c = c.to_be_bytes();
        let len = k.saturating_sub(c.len());
        sign.clear();
        sign.resize(len, 0);
        sign.append(&mut c);
        Ok(())
    }
    
    fn verify(&mut self, sign: &[u8], m_hash: &[u8]) -> Result<(), CryptoError> {
        let (prefix, h_len) = self.pkcs1_hash_info(m_hash.len())?;
        
        let (t_len, k) = (prefix.len() + h_len, self.kp.public_key().modulus_size());
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
        
        if em[0] != 0x00 || em[1] != 0x01 || &em[(k-t_len)..(k-h_len)] != prefix.as_slice() || em[k-t_len-1] != 0x00 ||
            &em[(k-h_len)..] != m_hash {
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
    fn pkcs1_hash_prefix(&self) -> Result<Vec<u8>, CryptoError> {
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
            Err(CryptoError::new(CryptoErrorKind::NotSupportUsage, format!("{} is not currently supported", std::any::type_name::<H>())))
        }
    }
    
    fn pkcs1_hash_info(&self, h_len: usize) -> Result<(Vec<u8>, usize), CryptoError> {
        let len = (self.hf.bits_len() + 7) >> 3;
        if len != h_len {
            Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "Invalid m_hash length"))
        } else {
            self.pkcs1_hash_prefix().map(|x| {(x, len)})
        }
    }
} 

