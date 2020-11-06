//! [PKCS #1 v2.2](https://www.cnblogs.com/mengsuenyan/p/13796306.html#rsassa-pss)
//! 


use crate::{Digest, CryptoError, CryptoErrorKind};
use crate::rsa::rsa::KeyPair;
use rmath::bigint::BigInt;

/// Encrypt scheme: RSAES-OAEP  
pub struct OAEP<H, R> {
    kp: KeyPair,
    // hash function(message digest function)
    hf: H,
    rd: R,
    // a label associated with the message, default is empty
    label: Vec<u8>,
    is_blinding: bool,
}

impl<H, R> OAEP<H, R>
    where H: Digest, R: rmath::rand::IterSource<u32> {
    pub fn set_label(&mut self, new_label: &[u8]) {
        self.label.clear();
        self.label.extend(new_label.iter());
    }
    
    fn encrypt(&mut self, cipher_txt: &mut Vec<u8>, msg: &[u8]) -> Result<(), CryptoError> {
        self.kp.public_key().is_valid()?;
        let (k, h_len) = (self.kp.public_key().modulus_size(), (self.hf.bits_len() + 7) >> 3);
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
        self.rd.iter_mut().take(h_len).for_each(|e| {
            em.push(((e >> 24) & 0xff) as u8);
            em.push(((e >> 16) & 0xff) as u8);
            em.push(((e >> 8) & 0xff) as u8);
            em.push((e & 0xff) as u8);
        });
        
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
    
    fn decrypt(&mut self, msg: &mut Vec<u8>, cipher_text: &[u8]) -> Result<(), CryptoError> {
        if cipher_text.is_empty() {
            return Err(CryptoError::new(CryptoErrorKind::InvalidPublicKey, "The cipher text is empty"));
        }
        
        self.kp.public_key().is_valid()?;
        
        let (k, h_len) = (self.kp.public_key().modulus_size(), (self.hf.bits_len() + 7) >> 3);
        if k < cipher_text.len() || k < ((h_len << 1) + 2) {
            return Err(CryptoError::new(CryptoErrorKind::InvalidPublicKey, "The public key modulus is too short"));
        }
        
        let c = BigInt::from_be_bytes(cipher_text);
        
        let m = if self.is_blinding {
            self.kp.decrypt::<R>(&c, Some(&mut self.rd))
        } else {
            self.kp.decrypt::<R>(&c, None)
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
        msg.extend((&em[(idx+1)..]).iter());
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
