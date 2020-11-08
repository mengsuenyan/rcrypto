//! [PKCS #1 v2.2](https://www.cnblogs.com/mengsuenyan/p/13796306.html#rsassa-pss)
//! 


use crate::{Digest, CryptoError, CryptoErrorKind, Cipher};
use crate::rsa::rsa::KeyPair;
use rmath::bigint::BigInt;
use std::cell::Cell;
use rmath::rand::IterSource;
use crate::rsa::{PublicKey, PrivateKey};

struct OAEPInner<H, R> {
    kp: KeyPair,
    // hash function(message digest function)
    hf: H,
    rd: R,
    // a label associated with the message, default is empty
    label: Vec<u8>,
    is_blinding: bool,
}

/// Encrypt scheme: RSAES-OAEP  
pub struct OAEP<H, R> {
    inner: Cell<OAEPInner<H, R>>
}

impl<H, R> OAEPInner<H, R>
    where H: Digest, R: IterSource<u32> {
    fn new(digest: H, rd: R, key_pair: KeyPair, label: Vec<u8>, is_enable_blinding: bool) -> Result<Self, CryptoError> {
        Ok(
            Self {
                kp: key_pair,
                hf: digest,
                rd,
                label,
                is_blinding: is_enable_blinding,
            }
        )
    }
    
    fn set_label(&mut self, new_label: &[u8]) {
        self.label.clear();
        self.label.extend(new_label.iter());
    }
    
    fn encrypt_inner(&mut self, cipher_txt: &mut Vec<u8>, msg: &[u8]) -> Result<(), CryptoError> {
        self.kp.public_key().is_valid()?;
        let (k, h_len) = (self.kp.public_key().modulus_len(), (self.hf.bits_len() + 7) >> 3);
        if msg.len() > (k - (h_len << 1) -2) {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "The length of message is too long"));
        }
        
        let mut lhash = Vec::with_capacity(h_len);
        self.hf.reset();
        self.hf.write(self.label.as_slice());
        self.hf.checksum(&mut lhash);
        
        let mut em = Vec::with_capacity(k);
        let (seed_bound, db_bound) = ((1, h_len + 1), (1+h_len, k));
        em.push(0x00u8);
        // seed
        self.rd.iter_mut().take((h_len + 3) >> 1).for_each(|e| {
            em.push(((e >> 24) & 0xff) as u8);
            em.push(((e >> 16) & 0xff) as u8);
            em.push(((e >> 8) & 0xff) as u8);
            em.push((e & 0xff) as u8);
        });
        em.truncate(h_len + 1);
        
        // db = lhash || ps || 0x01 || M
        em.append(&mut lhash);
        em.extend(std::iter::repeat(0u8).take(k.saturating_sub(msg.len() + (h_len << 1) + 2)));
        em.push(0x01);
        em.extend(msg.iter());
        
        if em.len() != k {
            return Err(CryptoError::new(CryptoErrorKind::InnerErr, "The encoding message not equal to modulus length"));
        }
        
        Self::mgf1_xor(em.as_mut_slice(), db_bound, seed_bound, h_len, &mut self.hf);
        Self::mgf1_xor(em.as_mut_slice(), seed_bound, db_bound, h_len, &mut self.hf);
        let m = BigInt::from_be_bytes(em.as_slice());
        let c = self.kp.public_key().encrypt(&m);
       
        let mut out = c.to_be_bytes();
        cipher_txt.clear();
        if out.len() < k {
            cipher_txt.resize(k - out.len(), 0);
        } else {
            out.truncate(k);
        }
        cipher_txt.append(&mut out);
        Ok(())
    }
    
    fn decrypt_inner(&mut self, msg: &mut Vec<u8>, cipher_text: &[u8]) -> Result<(), CryptoError> {
        if cipher_text.is_empty() {
            return Err(CryptoError::new(CryptoErrorKind::InvalidPublicKey, "The cipher text is empty"));
        }
        
        let kp = self.kp.private_key().ok_or(CryptoError::new(CryptoErrorKind::InvalidPrivateKey, "RSAES-OAEP: public key cannot be used for decryption"))?;
        
        kp.public_key().is_valid()?;
        
        let (k, h_len) = (kp.public_key().modulus_len(), (self.hf.bits_len() + 7) >> 3);
        if k < cipher_text.len() || k < ((h_len << 1) + 2) {
            return Err(CryptoError::new(CryptoErrorKind::InvalidPublicKey, "The public key modulus is too short"));
        }
        
        let c = BigInt::from_be_bytes(cipher_text);
        
        let m = if self.is_blinding {
            kp.decrypt::<R>(&c, Some(&mut self.rd))
        } else {
            kp.decrypt::<R>(&c, None)
        }?;

        let mut lhash = Vec::with_capacity(h_len);
        self.hf.reset();
        self.hf.write(self.label.as_slice());
        self.hf.checksum(&mut lhash);
        
        let mut em = m.to_be_bytes();
        let old_len = em.len();
        if k > old_len {
            em.resize(k, 0);
            em.rotate_right(k - old_len);
        } else {
            em.truncate(k);
        }
        
        if em[0] != 0x00 {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid message encoding format"));
        }
        
        let (seed_bound, db_bound) = ((1, h_len+1), (h_len + 1, em.len()));
        Self::mgf1_xor(em.as_mut_slice(), seed_bound, db_bound, h_len, &mut self.hf);
        Self::mgf1_xor(em.as_mut_slice(), db_bound, seed_bound, h_len, &mut self.hf);
        
        let lhash2_bound = (db_bound.0, db_bound.0 + h_len);
        if lhash.as_slice() != &em.as_slice()[(lhash2_bound.0)..(lhash2_bound.1)] {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid label hash value"));
        }
        
        let (rest_bound, mut idx) = ((db_bound.0 + h_len, db_bound.1), db_bound.0 + h_len);
        for &x in (&em[(rest_bound.0)..(rest_bound.1)]).iter() {
            idx += 1;
            if x != 0x00 {
                if x != 0x01 {
                    return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid message encoding format"));
                }
                break;
            }
        }
        
        msg.clear();
        msg.extend((&em[idx..]).iter());
        Ok(())
    }
    
    fn mgf1_xor(em: &mut [u8], obound: (usize, usize), sbound: (usize, usize), h_len: usize, hf: &mut H) {
        let (mut done, mut count) = (0, 0u32);
        let mut digest = Vec::with_capacity(h_len);
        
        while done < (obound.1 - obound.0) {
            let seed = &em[(sbound.0)..(sbound.1)];
            hf.reset();
            hf.write(seed);
            hf.write(count.to_be_bytes().as_ref());
            hf.checksum(&mut digest);
            
            (&mut em[(obound.0)..(obound.1)]).iter_mut().skip(done).zip(digest.iter()).for_each(|(a, &b)| {
                *a ^= b;
                done += 1;
            });
            
            count += 1;
        }
    }
}

impl<H, R> OAEP<H, R> 
    where H: Digest, R: IterSource<u32> {
    
    fn get_oaepinner(&self) -> & OAEPInner<H, R> {
        unsafe {
            & (*self.inner.as_ptr())
        }
    }
    
    fn get_oaepinner_mut(&self) -> &mut OAEPInner<H, R> {
        unsafe {
            &mut (*self.inner.as_ptr())
        }
    }
    
    /// digest message length in bytes
    pub fn digest_len(&self) -> usize {
        (self.get_oaepinner().hf.bits_len() + 7) >> 3
    }
    
    /// public key length in bytes
    pub fn modulus_len(&self) -> usize {
        self.public_key().modulus_len()
    }
    
    pub fn public_key(&self) -> &PublicKey {
        self.get_oaepinner().kp.public_key()
    }
    
    pub fn set_label(&mut self, label: Vec<u8>) {
        self.inner.get_mut().set_label(label.as_slice());
    }
    
    /// # Note  
    /// 
    /// This method do not check the the validity of the `key_pair`, because the `key_pair` 
    pub fn new_uncheck(digest: H, rd: R, key_pair: KeyPair, label: Vec<u8>, is_enable_blinding: bool) -> Result<Self, CryptoError> {
        let h_len = (digest.bits_len() + 7) >> 3;
        
        if key_pair.modulus_len() <= ((h_len << 1) + 2) {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "The modulus length is too short"));
        }
        
        let inner = OAEPInner::new(digest, rd, key_pair, label, is_enable_blinding)?;
        
        Ok(
            Self {
                inner: Cell::new(inner)
            }   
        )
    }
    
    pub fn new(digest: H, rd: R, key_pair: KeyPair, label: Vec<u8>, is_enable_bliding: bool) -> Result<Self, CryptoError> {
        if key_pair.private_key().is_some() {
            key_pair.private_key().unwrap().is_valid()?;
        } else {
            key_pair.public_key().is_valid()?;
        }
        
        Self::new_uncheck(digest, rd, key_pair, label, is_enable_bliding)
    }
    
    pub fn auto_generate_key(bits_len: usize, test_round_times: usize, digest: H, mut rd: R, label: Vec<u8>, is_enbale_bliding: bool) -> Result<Self, CryptoError> {
        let h_len = (digest.bits_len() + 7) >> 3;
        if bits_len <= ((h_len << 1) + 2) {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "bits len is too small"));
        }
        
        let key_ = PrivateKey::generate_key(bits_len, test_round_times, &mut rd)?;
        
        Self::new_uncheck(digest, rd, KeyPair::from(key_), label, is_enbale_bliding)
    }
    
    /// maximum message length in byte allowed to be encrypted
    pub fn max_message_len(&self) -> usize {
        self.modulus_len() - (self.digest_len() << 1) - 2
    }
}

impl<H, R> Cipher for OAEP<H, R> 
    where H: Digest, R: IterSource<u32> {
    type Output = ();
    fn block_size(&self) -> Option<usize> {
        None
    }

    /// the length of plaintext text should be less than or equal to `self.modulus_len() - 2*self.digest_len() - 2`;  
    fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<(), CryptoError> {
        let inner = self.get_oaepinner_mut();
        
        inner.encrypt_inner(dst, plaintext_block)
    }

    /// the length of cipher text should be equal to `self.modulus_len()`;
    fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<(), CryptoError> {
        let inner = self.get_oaepinner_mut();
        
        inner.decrypt_inner(dst, cipher_block)
    }
}

impl<H, R> OAEP<H, R>
    where H: Digest + Clone, R: IterSource<u32> {
    pub fn digest_func(&self) -> H {
        let mut h = self.get_oaepinner().hf.clone();
        h.reset();
        h
    }
}


impl<H, R> OAEP<H, R>
    where H: Digest, R: IterSource<u32> + Clone {
    pub fn rand_source(&self) -> R {
        self.get_oaepinner().rd.clone()
    }
}