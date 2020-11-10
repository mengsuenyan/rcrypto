//! [PKCS #1 v2.2](https://www.cnblogs.com/mengsuenyan/p/13796306.html#rsassa-pss)
//! 

use crate::{Digest, CryptoError, CryptoErrorKind, Signature};
use crate::rsa::{PublicKey, PrivateKey, SignatureContent};
use rmath::bigint::BigInt;
use crate::rsa::rsa::KeyPair;
use rmath::rand::IterSource;

/// Signature Scheme: RSASSA-PSS
pub struct PSS<H, R> {
    // SaltLength controls the length of the salt used in the PSS 
    // signature. `None` means auto generate the length by the PSS.
    kp: KeyPair,
    // salt length
    slen: usize,
    hf: H,
    rd: R,
    is_blinding: bool,
}

impl<H, R> PSS<H, R> 
    where H: Digest + Clone, R: IterSource<u32> {
    
    pub fn digest_func(&self) -> H {
        let mut h = self.hf.clone();
        h.reset();
        h
    }
}

impl<H, R> PSS<H, R>
    where H: Digest, R: IterSource<u32> + Clone {
    pub fn rand_source(&self) -> R {
        self.rd.clone()
    }
}

impl<H, R> PSS<H, R>
    where H: Digest, R: IterSource<u32> {

    /// digest message length in bytes
    pub fn digest_len(&self) -> usize {
        (self.hf.bits_len() + 7) >> 3
    }

    /// public key length in bytes
    pub fn modulus_len(&self) -> usize {
        self.kp.public_key().modulus_len()
    }
    
    pub fn public_key(&self) -> &PublicKey {
        self.kp.public_key()
    }
    
    fn compute_salt_len(salt_len: Option<usize>, h_len: usize, bits_len: usize) -> usize {
        match salt_len {
            Some(x) => {
                if x > 0 {
                    x
                } else {
                    ((bits_len + 7) >> 3).saturating_sub(2 + h_len)
                }
            },
            None => {
                h_len
            }
        }
    }
    
    /// `digest`: message digest generator;  
    /// `rd`: random number generator;  
    /// `salt_len` the length of salt in bytes, `None` means the salt length equal 
    /// to the `digest.len()`, `Some(0)` means that the salt length compute from the modulus bit length of public key. 
    /// `Some(x)` means that the salt length equal to `x`;  
    /// `is_enbale_blind`: enable RSA blinding;
    pub fn new_uncheck(digest: H, rd: R, key_pair: KeyPair, salt_len: Option<usize>, is_enable_blind: bool) -> Result<Self, CryptoError> {
        let h_len = (digest.bits_len() + 7) >> 3;
        let salt_len = Self::compute_salt_len(salt_len, h_len, key_pair.public_key().modulus().bits_len());

        let em_len = (key_pair.public_key().modulus().bits_len() - 1 + 7) >> 3;
        if em_len < (h_len + salt_len + 2) {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "The salt length is too long, or the modulus length is too short"));
        }
        
        Ok(
            Self {
                kp: key_pair,
                slen: salt_len,
                hf: digest,
                rd,
                is_blinding: is_enable_blind,
            }
        )
    }
    
    pub fn new(digest: H, rd: R, key_pair: KeyPair, salt_len: Option<usize>, is_enable_blind: bool) -> Result<Self, CryptoError> {
        if key_pair.private_key().is_some() {
            key_pair.private_key().unwrap().is_valid()?;
        } else {
            key_pair.public_key().is_valid()?;
        }
        
        Self::new_uncheck(digest, rd, key_pair, salt_len, is_enable_blind)
    }
    
    pub fn auto_generate_key(bits_len: usize, test_round_times: usize, digest: H, mut rd: R, salt_len: Option<usize>, is_enable_blind: bool) -> Result<Self,CryptoError> {
        let h_len = (digest.bits_len() + 7) >> 3;
        let salt_len = Self::compute_salt_len(salt_len, h_len, bits_len);
        if ((bits_len.saturating_sub(1) + 7) >> 3) < (h_len + salt_len + 2) {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "Ths bits_len is too small"));
        }
        
        let key_ = PrivateKey::generate_key(bits_len, test_round_times, &mut rd)?;
        
        Self::new_uncheck(digest, rd, KeyPair::from(key_), Some(salt_len), is_enable_blind)
    }

    /// maximum message length in byte allowed to be signature
    pub fn max_message_len(&self) -> usize {
        #[cfg(target_pointer_width = "32")]
        {
            u32::MAX as usize
        }
        
        #[cfg(target_pointer_width = "64")]
        {
            u64::MAX as usize
        }
    }
    
    #[inline]
    pub fn salt_len(&self) -> usize {
        self.slen
    }
    
    fn mgf1_xor(out: &mut [u8], seed: &[u8], hf: &mut H) {
        let (mut done, mut count) = (0, 0u32);
        let mut digest = Vec::with_capacity((hf.bits_len() + 7) >> 3);
        
        while done < out.len() {
            hf.reset();
            hf.write(seed);
            hf.write(count.to_be_bytes().as_ref());
            hf.checksum(&mut digest);
            
            out.iter_mut().skip(done).zip(digest.iter()).for_each(|(a, &b)| {
                *a ^= b;
                done += 1;
            });
            
            count += 1;
        }
    }
    
    /// `m_hash = Hash(Message)`
    pub(super) fn emsa_pss_encode(&mut self, em: &mut Vec<u8>, m_hash: &[u8], em_bits: usize, salt: &[u8]) -> Result<(), CryptoError> {
        let (h_len, s_len, em_len) = ((self.hf.bits_len() + 7) >> 3, salt.len(), (em_bits + 7) >> 3);
        
        if em_len < (h_len + s_len + 2) {
            return Err(CryptoError::new(CryptoErrorKind::InnerErr, format!("key size too small: {} < {}", em_len, h_len + s_len + 2)));
        }
        
        em.clear();
        em.resize(em_len, 0);
        
        let mut buf = Vec::with_capacity(h_len);
        self.hf.reset();
        self.hf.write(m_hash);
        self.hf.checksum(&mut buf);
        if h_len != buf.len() {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid hash length"));
        }
        
        const PREFIX: [u8;8] = [0u8;8];
        self.hf.reset();
        self.hf.write(PREFIX.as_ref());
        self.hf.write(buf.as_slice());
        self.hf.write(salt);
        self.hf.checksum(&mut buf);
        
        let (db_start, db_end) = (0, em_len - h_len - 1);
        let (h_start, h_end) = (db_end, em_len - 1);
        (&mut em.as_mut_slice()[h_start..h_end]).copy_from_slice(buf.as_slice());
        
        em[em_len - s_len - h_len - 2] = 0x01;
        (&mut em.as_mut_slice()[(db_end - s_len)..db_end]).copy_from_slice(salt);
        
        Self::mgf1_xor(&mut em.as_mut_slice()[db_start..db_end], buf.as_slice(), &mut self.hf);
        
        em[0] &= 0xffu8 >> ((em_len << 3) - em_bits);
        
        em[em_len - 1] = 0xbc;
        Ok(())
    }
    
    /// The method will auto find salt length when the `s_len` is `None`;
    pub(super) fn emsa_pss_verify(&mut self, em: &[u8], m_hash: &[u8], em_bits: usize) -> Result<(), CryptoError> {
        let h_len = (self.hf.bits_len() + 7) >> 3;
        
        let mut buf = Vec::with_capacity(h_len);
        self.hf.reset();
        self.hf.write(m_hash);
        self.hf.checksum(&mut buf);
        
        let m_hash = buf.as_slice();
        if h_len != m_hash.len() {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid hash length"));
        }
        
        let em_len = (em_bits + 7) >> 3;
        if (em_len != em.len()) || (em_len < (h_len + self.salt_len() + 2)) {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid encdoe message length"));
        }
            
        if em[em_len - 1] != 0xbc {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid tail flag"));
        }
        
        let (db_start, db_end) = (0, em_len - h_len - 1);
        let (h_start, h_end) = (db_end, em_len - 1);
        
        if (em[0] & (0xffu8 << (8 - ((em_len << 3) - em_bits)))) != 0 {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid head tag"));
        }
        
        let mut db = em[db_start..db_end].to_vec();
        let h = &em[h_start..h_end];
        Self::mgf1_xor(db.as_mut_slice(), h, &mut self.hf);
        
        db[0] &= 0xff >> ((em_len >> 3) - em_bits);

        for &e in db.iter().take(em_len - h_len - self.salt_len() - 2) {
            if e != 0x00 {
                return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid db head"));
            }
        }

        if db[em_len - h_len - self.salt_len() - 2] != 0x01 {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid db body"));
        }
        
        const PREFIX: [u8;8] = [0;8];
        self.hf.reset();
        self.hf.write(PREFIX.as_ref());
        self.hf.write(m_hash);
        self.hf.write(&db.as_slice()[(db.len() - self.salt_len())..]);
        
        db.clear();
        self.hf.checksum(&mut db);
        
        if db.as_slice() != h {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Different signature"))
        }
        
        Ok(())
    }

    /// signPSSWithSalt calculates the signature of hashed using PSS [1] with specified salt.
    /// Note that hashed must be the result of hashing the input message using the
    /// given hash function. salt is a random sequence of bytes whose length will be
    /// later used to verify the signature.
    fn sign_with_salt(&mut self, sign: &mut Vec<u8>, m_hash: &[u8], salt: &[u8]) -> Result<(), CryptoError> {
        let n_bits = self.kp.public_key().modulus().bits_len();
        self.emsa_pss_encode(sign, m_hash, n_bits - 1, salt)?;
        let m = BigInt::from_be_bytes(sign);
        
        let kp = self.kp.private_key().ok_or(CryptoError::new(CryptoErrorKind::InvalidPrivateKey, "RSASSA-PSS: public key cannot be used for signing"))?;
        let c = if self.is_blinding {
            kp.decrypt_and_check::<R>(&m, Some(&mut self.rd))
        } else {
            kp.decrypt_and_check::<R>(&m, None)
        }?;
        let mut s = c.to_be_bytes();
        let (new_len, old_len) = ((n_bits + 7) >> 3, s.len());
        
        sign.clear();
        sign.resize(new_len.saturating_sub(old_len), 0);
        sign.append(&mut s);
        Ok(())
    }
    
    fn sign_inner(&mut self, sign: &mut Vec<u8>, m_hash: &[u8]) -> Result<(), CryptoError> {
        let salt_len = self.salt_len();
        let mut salt = Vec::with_capacity(salt_len);
        self.rd.iter_mut().take((salt_len + 3) >> 2).for_each(|x| {
            x.to_be_bytes().iter().for_each(|&y| {salt.push(y);});
        });
        salt.truncate(salt_len);
        
        self.sign_with_salt(sign, m_hash, salt.as_slice())
    }
    
    fn verify_inner(&mut self, sign: &[u8], m_hash: &[u8]) -> Result<(), CryptoError> {
        let n_bits = self.kp.public_key().modulus().bits_len();
        
        if sign.len() != ((n_bits + 7) >> 3) {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Singanature length doesn't match"));
        }
        
        let s = BigInt::from_be_bytes(sign);
        let m = self.kp.public_key().encrypt(&s);
        
        let em_bits = n_bits - 1;
        let em_len = (em_bits + 7) >> 3;
        if em_len < ((m.bits_len() + 7) >> 3) {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid encode message length"));
        }
        
        let mut em = m.to_be_bytes();
        let old_len = em.len();
        em.resize(em_len, 0);
        em.rotate_right(em_len - old_len);
        
        self.emsa_pss_verify(em.as_slice(), m_hash, em_bits)
    }
}

impl<H, R> Signature<SignatureContent> for PSS<H, R>
    where H: Digest, R: IterSource<u32> {
    type Output = ();

    /// the length of message should be less than or equal to `self.digest_len() + self.salt_len() + 2`
    fn sign(&mut self, signature: &mut SignatureContent, message: &[u8]) -> Result<Self::Output, CryptoError> {
        self.sign_inner(signature.as_mut(), message)
    }

    /// the length of signature should be equal to `self.modulus_len()`
    fn verify(&mut self, signature: &SignatureContent, message: &[u8]) -> Result<Self::Output, CryptoError> {
        self.verify_inner(signature.as_ref(), message)
    }
}