//! [RSA密码学规范PKCS#1 v2.2](https://www.cnblogs.com/mengsuenyan/p/13796306.html#%E5%8F%82%E8%80%83%E8%B5%84%E6%96%99)
//! 
//! 
//! 
//! reference: PKCS v2.2

use rmath::bigint::{BigInt, Nat};
use crate::{CryptoError, CryptoErrorKind};
use rmath::rand::IterSource;

pub struct PublicKey {
    // modulus, $n = p \cdot q$
    n: BigInt,
    // public exponent
    e: BigInt,
}

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        Self {
            n: self.n.deep_clone(),
            e: self.e.deep_clone(),
        }
    }
}

// chinese remainder theorem
struct CRTValue {
    // the exponent of the prime factor r: $d \mod (prime-1)$
    exp: BigInt,
    // CRT coefficients: $r \cdot coeff \equiv 1 \mod prime$
    coeff: BigInt,
    //prime factor: $r = p \cdot q$
    r: BigInt,
}

impl Clone for CRTValue {
    fn clone(&self) -> Self {
        Self {
            exp: self.exp.deep_clone(),
            coeff: self.coeff.deep_clone(),
            r: self.r.deep_clone(),
        }
    }
}

struct PrecomputedValues {
    // $e \cdot d_p \equiv 1 \mod (p-1)$
    d_p: BigInt,
    // $e \cdot d_q \equiv 1 \mod (q-1)$
    d_q: BigInt,
    // $q \cdot q_inv \equiv 1 \mod p$
    q_inv: BigInt,

    // CRTValues is used for the 3rd and subsequent primes. Due to a
    // historical accident, the CRT for the first two primes is handled
    // differently in PKCS#1 and interoperability is sufficiently
    // important that we mirror this.
    crt_values: Vec<CRTValue>,
}

impl Clone for PrecomputedValues {
    fn clone(&self) -> Self {
        Self {
            d_p: self.d_p.deep_clone(),
            d_q: self.d_q.deep_clone(),
            q_inv: self.q_inv.deep_clone(),
            crt_values: self.crt_values.clone(),
        }
    }
}

pub struct PrivateKey {
    pk: PublicKey,
    // private exponent
    d: BigInt,
    // prime factors of n, has >= 2 elements
    primes: Vec<BigInt>,

    // Precomputed contains precomputed values that speed up private
    // operations, if available.
    precomputed: PrecomputedValues,
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        let mut primes = Vec::with_capacity(self.primes.len());
        self.primes.iter().for_each(|e| {primes.push(e.deep_clone());});
        
        Self {
            pk: self.pk.clone(),
            d: self.d.clone(),
            primes,
            precomputed: self.precomputed.clone(),
        }
    }
}

impl PublicKey {
    pub fn from_bigint(modulus: &BigInt, exponent: &BigInt) -> Result<Self, CryptoError> {
        if modulus.signnum() != Some(1) || exponent.signnum() != Some(1) {
            Err(CryptoError::new(CryptoErrorKind::InvalidParameter, ""))
        } else {
            Self::from_nat(modulus.as_ref(), exponent.as_ref())
        }
    }
    
    pub fn from_nat(modulus: &Nat, exponent: &Nat) -> Result<Self, CryptoError> {
        if modulus <= exponent || exponent < &3u32 {
            Err(CryptoError::new(CryptoErrorKind::InvalidParameter, ""))
        } else {
            Ok(
                Self {
                    n: BigInt::from(modulus.clone()),
                    e: BigInt::from(exponent.clone()),
                }
            )
        }
    }
    
    /// big endian  
    pub fn from_be_bytes(modulus: &[u8], exponent: &[u8]) -> Result<Self, CryptoError> {
        let (n, e) = (Nat::from_be_bytes(modulus), Nat::from_be_bytes(exponent));
        Self::from_nat(&n, &e)
    }
    
    /// little endian
    pub fn from_le_bytes(modulus: &[u8], exponent: &[u8]) -> Result<Self, CryptoError> {
        let (n, e) = (Nat::from_le_bytes(modulus), Nat::from_le_bytes(exponent));
        Self::from_nat(&n, &e)
    }
    
    /// return this modulus(n) size in bytes
    pub fn modulus_len(&self) -> usize {
        (self.n.bits_len() + 7) >> 3
    }
    
    pub(super) fn modulus(&self) -> &BigInt {
        &self.n
    }
    
    pub(super) fn exponent(&self) -> &BigInt {
        &self.e
    }
    
    pub(super) fn is_valid(&self) -> Result<(), CryptoError> {
        if self.n.is_nan() {
            Err(CryptoError::new(CryptoErrorKind::InvalidPublicKey, "public modulus is a NaN"))
        } else if self.e < BigInt::from(2u32) {
            Err(CryptoError::new(CryptoErrorKind::InvalidPublicKey, "public exponent is too small"))
        } else if self.e > BigInt::from((1u32 << 31) - 1) {
            Err(CryptoError::new(CryptoErrorKind::InvalidPublicKey, "public exponent is too large"))
        } else {
            Ok(())
        }
    }
    
    /// RSAEP: RSA encrypt primitive  
    /// $m^e \mod n$
    pub fn encrypt(&self, m: &BigInt) -> BigInt {
        m.exp(&self.e, &self.n)
    }
}

pub struct KeyPair {
    pub_key: Option<PublicKey>,
    pri_key: Option<PrivateKey>,
}

impl KeyPair {
    #[inline]
    pub(super) fn private_key(&self) -> Option<&PrivateKey> {
        self.pri_key.as_ref()
    }
    
    #[inline]
    pub(super) fn public_key(&self) -> &PublicKey {
        if self.pri_key.is_some() {
            self.pri_key.as_ref().unwrap().public_key()
        } else {
            self.pub_key.as_ref().unwrap()
        }
    }
    
    #[inline]
    pub(super) fn modulus_len(&self) -> usize {
        self.public_key().modulus_len()
    }
}

impl From<PublicKey> for KeyPair {
    /// used to verify signature
    fn from(key_: PublicKey) -> Self {
        Self {
            pub_key: Some(key_),
            pri_key: None,
        }
    }
}

impl From<PrivateKey> for KeyPair {
    fn from(key_: PrivateKey) -> Self {
        Self {
            pub_key: None,
            pri_key: Some(key_),
        }
    }
}

impl PrivateKey {
    pub fn modulus_len(&self) -> usize {
        self.pk.modulus_len()
    }
    
    pub(super) fn modulus(&self) -> &BigInt {
        &self.pk.n
    }
    
    pub fn public_key(&self) -> &PublicKey {
        &self.pk
    }
    
    pub(super) fn exponent(&self) -> &BigInt {
        &self.d
    }
    
    /// RSADP: RSA decrypt primitive  
    /// if `rd` is some, then enabled RSA blinding
    pub fn decrypt<R: IterSource<u32>>(&self, c: &BigInt, rd: Option<&mut R>) -> Result<BigInt, CryptoError> {
        if c > &self.pk.n {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "The cipher text integer is too big"));
        }
        
        if self.pk.n.is_nan() || self.pk.n == 0u32 {
            return Err(CryptoError::new(CryptoErrorKind::InvalidPrivateKey, "Invalid modulus"));
        }
        
        if self.d.is_nan() {
            return Err(CryptoError::new(CryptoErrorKind::InvalidPrivateKey, "Private exponent is empty"));
        }
        
        let (c, ir) = match rd {
            Some(rnd) => {
                // Blinding enabled. Blinding involves multiplying c by r^e.
                // Then the decryption operation performs (m^e * r^e)^d mod n
                // which equals mr mod n. The factor of r can then be removed
                // by multiplying by the multiplicative inverse of r.
                let (r, ir) = loop {
                    let r = self.pk.n.random(rnd);
                    
                    let r = if r == 0u32 {
                        BigInt::from(1u32)
                    } else {
                        r
                    };
                    
                    let mi = r.mod_inverse(self.pk.n.clone());
                    if !mi.is_nan() {
                        break (r, Some(mi));
                    }
                };
                
                let mut r_powe = r.exp(&self.pk.e, &self.pk.n);
                r_powe *= c.clone();
                r_powe.rem_euclid_assign(self.pk.n.clone());
                (r_powe, ir)
            },
            None => {
                (c.clone(), None)
            },
        };
        
        let mut m = if self.precomputed.d_p.is_nan() {
            // first private key representation
            c.exp(&self.d, &self.pk.n)
        } else {
            // second private key representation
            let (mut m1, m2) = (
                c.exp(&self.precomputed.d_p, &self.primes[0]),
                c.exp(&self.precomputed.d_q, &self.primes[1]),
            );
            m1 -= m2.clone();
            if m1.signnum().unwrap() < 0 {
                m1 += self.primes[0].clone();
            }
            m1 *= self.precomputed.q_inv.clone();
            m1.rem_euclid_assign(self.primes.first().unwrap().clone());
            m1 *= self.primes[1].clone();
            m1 += m2.clone();
            
            // m1 as m
            for (values, prime) in self.precomputed.crt_values.iter().zip(self.primes.iter().skip(2)) {
                let mut m_i = c.exp(&values.exp, prime);
                m_i -= m1.clone();
                m_i *= values.coeff.clone();
                m_i.rem_euclid_assign(prime.clone());
                if m_i.signnum().unwrap() < 0 {
                    m_i += prime.clone();
                }
                
                m_i *= values.r.clone();
                m1 += m_i;
            }
            
            m1
        };
        
        match ir {
            Some(blind) => {
                m *= blind;
                m.rem_euclid_assign(self.pk.n.clone());
                Ok(m)
            },
            None => {
                Ok(m)
            }
        }
    }
    
    
    /// decrypt the cipher integer `c` and check its validation using the public key
    pub fn decrypt_and_check<R: IterSource<u32>>(&self, c: &BigInt, rd: Option<&mut R>) -> Result<BigInt, CryptoError> {
        let m = self.decrypt(c, rd)?;
        
        let check = self.pk.encrypt(&m);
        
        if c != &check {
            Err(CryptoError::new(CryptoErrorKind::InnerErr, "Internal error"))
        } else {
            Ok(m)
        }
    }
    
    /// validate the private key is valid
    pub fn is_valid(&self) -> Result<(), CryptoError> {
        self.public_key().is_valid()?;
        
        let bigone = BigInt::from(1u32);
        let mut modulus = BigInt::from(0u32);
        for prime in self.primes.iter() {
            if prime <= &bigone {
                return Err(CryptoError::new(CryptoErrorKind::InvalidPrivateKey, "Invalid prime value"));
            }
            modulus *= prime.clone();
        }
        
        if &modulus != self.modulus() {
            return Err(CryptoError::new(CryptoErrorKind::InvalidPrivateKey, "Invalid modulus"));
        }
        
        // Check that de ≡ 1 mod p-1, for each prime.
        // This implies that e is coprime to each p-1 as e has a multiplicative
        // inverse. Therefore e is coprime to lcm(p-1,q-1,r-1,...) =
        // exponent(ℤ/nℤ). It also implies that a^de ≡ a mod p as a^(p-1) ≡ 1
        // mod p. Thus a^de ≡ a mod n for all a coprime to n, as required.
        let de = self.exponent().clone() * self.public_key().exponent().clone();
        
        for prime in self.primes.iter() {
            let pminus1 = prime.clone() - bigone.clone();
            let congruence = de.rem_euclid(pminus1);
            if congruence != bigone {
                return Err(CryptoError::new(CryptoErrorKind::InvalidPrivateKey, "Invalid exponent"));
            }
        }
        
        Ok(())
    }

    /// `generate_key` generates an RSA keypair of the given bit size using the
    /// random source random (for example, crypto/rand.Reader).
    /// 
    /// `prime_test_round_num`(n) means the number of test rounds, for any odd number that great than 2 and positive integer n, the probability of error 
    /// in MillerRabinPrimeTest is at most $2^{-n}$.
    pub fn generate_key<R: IterSource<u32>>(bits_len: usize, prime_test_round_num: usize,  rd: &mut R) -> Result<PrivateKey, CryptoError> {
        Self::generate_multi_prime_key(2, bits_len, prime_test_round_num, rd)
    }

    /// This method convert from golang source code.  
    /// GenerateMultiPrimeKey generates a multi-prime RSA keypair of the given bit
    /// size and the given random source, as suggested in [1]. Although the public
    /// keys are compatible (actually, indistinguishable) from the 2-prime case,
    /// the private keys are not. Thus it may not be possible to export multi-prime
    /// private keys in certain formats or to subsequently import them into other
    /// code.
    ///
    /// Table 1 in [2] suggests maximum numbers of primes for a given size.
    ///
    /// [1] US patent 4405829 (1972, expired)
    /// [2] http://www.cacr.math.uwaterloo.ca/techreports/2006/cacr2006-16.pdf
    /// 
    /// `prime_test_round_num`(n) means the number of test rounds, for any odd number that great than 2 and positive integer n, the probability of error 
    /// in MillerRabinPrimeTest is at most $2^{-n}$.
    pub fn generate_multi_prime_key<R: IterSource<u32>>(n_primes: usize, bits: usize, prime_test_round_num: usize, rd: &mut R) -> Result<PrivateKey, CryptoError> {
        if n_primes < 2 {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "n_primes must be great or equal to 2"));
        }
        
        if bits < 64 {
            let prime_limit= (1u64 << (bits / n_primes)) as f64;
            // pi approximates the number of primes less than primeLimit
            let mut pi = prime_limit / (prime_limit.ln() - 1f64);
            
            // Generated primes start with 11 (in binary) so we can only
            // use a quarter of them.
            pi /= 4f64;
            // Use a factor of two to ensure that key generation terminates
            // in a reasonable amount of time.
            pi /= 2f64;
            if pi <= (n_primes as f64) {
                return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "Too few primes of given length to generatge an RSA key"));
            }
        }
        
        let bigone = BigInt::from(1u32);
        let pub_exp = BigInt::from(65537u32);
        let mut primes = Vec::with_capacity(n_primes);
        let (pri_exp, modulus) = 'next_set_of_primes: loop {
            primes.clear();
            let mut cbits = bits;
            // crypto/rand should set the top two bits in each prime.
            // Thus each prime has the form
            //   p_i = 2^bitlen(p_i) × 0.11... (in base 2).
            // And the product is:
            //   P = 2^cbits × α
            // where α is the product of nprimes numbers of the form 0.11...
            //
            // If α < 1/2 (which can happen for nprimes > 2), we need to
            // shift cbits to compensate for lost bits: the mean value of 0.11...
            // is 7/8, so cbits + shift - nprimes * log2(7/8) ~= bits - 1/2
            // will give good results.
            if n_primes >= 7 {
                cbits += (n_primes - 2) / 5
            }
            
            for i in 0..n_primes {
                let prime = match Nat::generate_prime(cbits / (n_primes - i), prime_test_round_num, rd) {
                    Ok(nat) => {
                        BigInt::from(nat)
                    },
                    Err(e) => {
                        return Err(CryptoError::new(CryptoErrorKind::OuterErr, e));
                    }
                };
                
                cbits -= prime.bits_len();
                primes.push(prime);
            }

            // Make sure that primes is pairwise unequal.
            primes.dedup();
            if primes.len() != n_primes {
                continue'next_set_of_primes;
            }

            let (mut n, mut totient) = (BigInt::from(1u32), BigInt::from(1u32));
            for prime in primes.iter() {
                n *= prime.clone();
                let pm1 = prime.clone() - bigone.clone();
                totient *= pm1;
            }
            
            if n.bits_len() != bits {
                // This should never happen for n_primes == 2 because
                // crypto/rand should set the top two bits in each prime.
                // For n_primes > 2 we hope it does not happen often.
                continue 'next_set_of_primes;
            }

            let pri_exp = pub_exp.mod_inverse(totient);

            if !pri_exp.is_nan() {
                break (pri_exp, n);
            }
        };
        
        let precomputed = PrecomputedValues::new(
            primes[0].clone(), primes[1].clone(), pri_exp.clone(), &primes.as_slice()[2..]
        );
        
        Ok(
            PrivateKey {
                pk: PublicKey {
                    n: modulus,
                    e: pub_exp,
                },
                d: pri_exp,
                primes,
                precomputed,
            }
        )
    }
}

impl PrecomputedValues {
    fn new(p: BigInt, q: BigInt, d: BigInt, primes: &[BigInt]) -> Self {
        let bigone = BigInt::from(1u32);
        let d_p = d.rem_euclid(p.clone() - bigone.clone());
        let d_q = d.rem_euclid(q.clone() - bigone.clone());
        let q_inv = q.mod_inverse(p.clone());
        let mut r = p.clone() * q.clone();
        let mut crt_values = Vec::with_capacity(primes.len());
        
        for prime in primes.iter() {
            let exp = d.rem_euclid(prime.clone() - bigone.clone());
            let rd = r.deep_clone();
            let coeff = r.mod_inverse(prime.clone());
            
            r *= prime.clone();
            crt_values.push(CRTValue::new(exp, coeff, rd));
        }
        
        Self {
            d_p,
            d_q,
            q_inv,
            crt_values,
        }
    }
}


impl CRTValue {
    fn new(exp: BigInt, coeff: BigInt, r: BigInt) -> Self {
        Self {
            exp,
            coeff,
            r
        }
    }
}