use rmath::bigint::{BigInt, Nat};
use crate::{Digest, CryptoError, CryptoErrorKind, Signature};
use rmath::rand::IterSource;
use std::fmt::{Display, Formatter, Debug};
use crate::dsa::signature::SignatureContent;

/// FIPS 186-4  
/// DSA domain parameters p,q,g  
pub struct DomainParameters {
    // gcd(p-1,q) = 1
    p: BigInt,
    q: BigInt,
    // |<g>| = q, g in GF(p);
    g: BigInt,
}

impl Clone for DomainParameters {
    fn clone(&self) -> Self {
        Self {
            p: self.p.deep_clone(),
            q: self.q.deep_clone(),
            g: self.g.deep_clone(),
        }
    }
}

pub struct PublicKey {
    dp: DomainParameters,
    // public key, y = g^x \mod p
    y: BigInt,
}

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        Self {
            dp: self.dp.clone(),
            y: self.y.deep_clone(),
        }
    }
}

pub struct PrivateKey {
    pk: PublicKey,
    // private key, x belong to [1,q-1]
    x: BigInt,
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        Self {
            pk: self.pk.clone(),
            x: self.x.deep_clone(),
        }
    }
}

pub struct DSA<H, R> {
    hf: H,
    rd: R,
    key_pair: KeyPair,
}

impl<H, R> DSA<H, R>
    where R: IterSource<u32> 
{
    fn generate_parameters_inner(rd: &mut R, l_len: usize, n_len: usize, test_round_times: usize) -> Result<DomainParameters, CryptoError> {
        let one = BigInt::from(1u32);
        
        let mut p_bytes = Vec::with_capacity(l_len >> 3);
        let (p, q) = 'generate_primes: loop {
            let q = Nat::generate_prime(n_len, test_round_times, rd)
                .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::OuterErr, e))})?;
            for _ in 0..(l_len << 2) {
                p_bytes.clear();
                for e in rd.iter_mut() {
                    p_bytes.push(((e >> 24) & 0xff) as u8);
                    p_bytes.push(((e >> 16) & 0xff) as u8);
                    p_bytes.push(((e >> 8) & 0xff) as u8);
                    p_bytes.push((e & 0xff) as u8);
                    if p_bytes.len() >= (l_len >> 3) {
                        break;
                    }
                }
                p_bytes.truncate(l_len >> 3);
                p_bytes[(l_len >> 3) - 1] |= 1;
                p_bytes[0] |= 0x80;
                let mut p = Nat::from_be_bytes(p_bytes.as_slice());
                let rem = p.clone() % q.clone();
                p += 1u32;
                if rem != 0u32 {
                    p -= rem;
                }
                
                if p.bits_len() < l_len {
                    continue;
                }
                
                if !p.probably_prime_test(test_round_times, rd) {
                    continue;
                }
                
                break 'generate_primes (BigInt::from(p), BigInt::from(q));
            } 
        };
        
        let mut h = BigInt::from(2u32);
        let mut pm1 = p.clone() - one.clone();
        pm1.div_euclid_assign(q.clone());
        let e = pm1;
        
        loop {
            let g = h.exp(&e, &p);
            if g == 1u32 {
                h += one.clone();
                continue;
            }
            
            return Ok(
                DomainParameters {
                    p,
                    q,
                    g,
                }
            );
        }
    }
    
    fn generate_key_inner(dp: DomainParameters, rd: &mut R) -> Result<PrivateKey, CryptoError> {
        let x = loop {
            let x = dp.q.random(rd);
            if x != 0u32 && x < dp.q {
                break x;
            }
        };
        
        let y = dp.g.exp(&x, &dp.p);
        
        Ok(
            PrivateKey {
                pk: PublicKey {
                    dp, 
                    y,
                },
                x,
            }
        )
    }

    /// fermatInverse calculates the inverse of k in GF(P) using Fermat's method.
    /// This has better constant-time properties than Euclid's method (implemented
    /// in math/big.Int.ModInverse) although math/big itself isn't strictly
    /// constant-time so it's not perfect.
    fn fermat_inverse(k: &BigInt, p: &BigInt) -> BigInt {
        let two = BigInt::from(2u32);
        let pm2 = p.clone() - two;
        k.exp(&pm2, &p)
    }
    
    /// FIPS 186-4, 4.2, L=1024, N=160
    pub fn l1024_n160(rd: &mut R) -> Result<DomainParameters, CryptoError> {
        let (l, n) = (1024, 160);
        Self::generate_parameters_inner(rd, l, n, Self::test_round_times())
    }
    
    pub fn l1024_n160_key(rd: &mut R) -> Result<PrivateKey, CryptoError> {
        let dp = Self::l1024_n160(rd)?;
        Self::generate_key_inner(dp, rd)
    }

    /// FIPS 186-4, 4.2, L=2048, N=224
    pub fn l2048_n224(rd: &mut R) -> Result<DomainParameters, CryptoError> {
        let (l, n) = (2048, 224);
        Self::generate_parameters_inner(rd, l, n, Self::test_round_times())
    }
    
    pub fn l2048_n224_key(rd: &mut R) -> Result<PrivateKey, CryptoError> {
        let dp = Self::l2048_n224(rd)?;
        Self::generate_key_inner(dp, rd)
    }

    /// FIPS 186-4, 4.2, L=2048, N=256
    pub fn l2048_n256(rd: &mut R) -> Result<DomainParameters, CryptoError> {
        let (l, n) = (2048, 256);
        Self::generate_parameters_inner(rd, l, n, Self::test_round_times())
    }
    
    pub fn l2048_n256_key(rd: &mut R) -> Result<PrivateKey, CryptoError> {
        let dp = Self::l2048_n256(rd)?;
        Self::generate_key_inner(dp, rd)
    }

    /// FIPS 186-4, 4.2, L=3072, N=256
    pub fn l3072_n256(rd: &mut R) -> Result<DomainParameters, CryptoError> {
        let (l, n) = (3072, 256);
        Self::generate_parameters_inner(rd, l, n, Self::test_round_times())
    }
    
    pub fn l3072_n256_key(rd: &mut R) -> Result<PrivateKey, CryptoError> {
        let dp = Self::l3072_n256(rd)?;
        Self::generate_key_inner(dp, rd)
    }
    
    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }
}

impl<H, R> DSA<H, R> 
    where H: Digest + Clone {
    pub fn digest_func(&self) -> H {
        let mut hf = self.hf.clone();
        hf.reset();
        hf
    }
}

impl<H, R> DSA<H, R>
    where R: IterSource<u32> + Clone {
    pub fn rand_source(&self) -> R {
        self.rd.clone()
    }
}

impl<H, R> DSA<H, R>
    where H: Digest, R: IterSource<u32> {
    pub fn new_uncheck(hf: H, rd: R, key_pair: KeyPair) -> Result<Self, CryptoError> {
        Ok(
            Self {
                hf,
                rd,
                key_pair,
            }
        )
    }
    
    pub fn new_with_l1024_n160(hf: H, mut rd: R) -> Result<Self, CryptoError> {
        let key = Self::l1024_n160_key(&mut rd)?;
        Self::new_uncheck(hf, rd, KeyPair::from(key))
    }
    
    pub fn new_with_l2048_n224(hf: H, mut rd: R) -> Result<Self, CryptoError> {
        let key = Self::l2048_n224_key(&mut rd)?;
        Self::new_uncheck(hf, rd, KeyPair::from(key))
    }
    
    pub fn new_with_l2048_n256(hf: H, mut rd: R) -> Result<Self, CryptoError> {
        let key = Self::l2048_n256_key(&mut rd)?;
        Self::new_uncheck(hf, rd, KeyPair::from(key))
    }
    
    pub fn new_with_l3072_n256(hf: H, mut rd: R) -> Result<Self, CryptoError> {
        let key = Self::l3072_n256_key(&mut rd)?;
        Self::new_uncheck(hf, rd, KeyPair::from(key))
    }
    
    /// FIPS 186-4 4.6  
    /// (r, s)
    fn sign_inner(&mut self, msg: &[u8]) -> Result<(BigInt, BigInt), CryptoError> {
        let pk = self.key_pair.private_key().ok_or(CryptoError::new(CryptoErrorKind::InvalidPrivateKey, "KeyPair is only a public key"))?;
        let dp = pk.domain_parameters();
        let n = dp.q.bits_len();
        
        if dp.q.signnum() != Some(1) || dp.p.signnum() != Some(1) || dp.g.signnum() != Some(1)
            || pk.x.signnum() != Some(1) || (n & 7) != 0 {
            return Err(CryptoError::new(CryptoErrorKind::InvalidPrivateKey, "Invalid public key"));
        }
        
        let h_len = (self.hf.bits_len() + 7) >> 3;
        let mut hm = Vec::with_capacity(h_len);
        self.hf.reset();
        self.hf.write(msg);
        self.hf.checksum(&mut hm);
        
        let n = n >> 3;
        for _ in 0..10 {
            let k = loop {
                let k = dp.q.random(&mut self.rd);
                if k.signnum() == Some(1) && k.as_ref() > &0u32 {
                    break k;
                }
            };
            
            let mut r = dp.g.exp(&k, &dp.p);
            r.rem_euclid_assign(dp.q.clone());
            
            if r.signnum() != Some(1) {
                continue;
            }

            let kinv = Self::fermat_inverse(&k, &dp.q);
            let tmp = std::cmp::min(h_len, n);
            let z = BigInt::from_be_bytes(&hm.as_slice()[..tmp]);
            let mut s = pk.x.clone() * r.clone();
            s += z;
            s.rem_euclid_assign(dp.q.clone());
            s *= kinv;
            s.rem_euclid_assign(dp.q.clone());
            
            if s.signnum() == Some(1) {
                return Ok((r, s))
            }
        };

        // Only degenerate private keys will require more than a handful of
        // attempts.
        Err(CryptoError::new(CryptoErrorKind::InvalidPrivateKey, "May be a degenerate private key"))
    }
    
    /// FIPS 186-4 4.7
    fn verify_inner(&mut self, msg: &[u8], r: &BigInt, s: &BigInt) -> Result<(), CryptoError> {
        let pk = self.key_pair.public_key();
        let dp = pk.domain_parameters();
        let n = dp.q.bits_len();
        
        if dp.p.signnum() != Some(1) || (n & 7) != 0 {
            return Err(CryptoError::new(CryptoErrorKind::InvalidPublicKey, ""));
        }
        
        if r.signnum() != Some(1) || s.signnum() != Some(1) || r >= &dp.q || s >= &dp.q {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid signature content"));
        }
        
        let w = s.mod_inverse(dp.q.clone());
        if w.is_nan() || w.as_ref() == &0u32 {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, "Invalid signature content"));
        }
        
        let h_len = (self.hf.bits_len() + 7) >> 3;
        let mut hm = Vec::with_capacity(h_len);
        self.hf.reset();
        self.hf.write(msg);
        self.hf.checksum(&mut hm);
        
        let mut z = BigInt::from_be_bytes(hm.as_slice());
        z *= w.clone();
        let mut u1 = z;
        u1.rem_euclid_assign(dp.q.clone());
        let mut u2 = r.clone() * w;
        u2.rem_euclid_assign(dp.q.clone());
        let mut v = dp.g.exp(&u1, &dp.p);
        let u2 = pk.y.exp(&u2, &dp.p);
        v *= u2;
        v.rem_euclid_assign(dp.p.clone());
        v.rem_euclid_assign(dp.q.clone());
        
        if &v == r {
            Ok(())
        } else {
            Err(CryptoError::new(CryptoErrorKind::VerificationFailed, ""))
        }
    }
}

impl<H, R> DSA<H, R> {
    /// the round number of Miller-Rabin primality tests
    /// 
    /// FIPS-186, Table C.1
    pub const fn test_round_times() -> usize {
        64
    }

}

impl DomainParameters {
    #[allow(unused)]
    fn check_pq_len(p: usize, q: usize) -> bool {
        if (p == 1024  && q == 160) || (p == 2048 && q == 224) 
            || (p == 2048 && q == 256) || (p == 3072 && q == 256) {
            true
        } else {
            false
        }
    }
    
    /// (p,q,g)
    #[allow(unused)]
    pub(super) fn unwrap(&self) -> (&BigInt, &BigInt, &BigInt) {
        (&self.p, &self.q, &self.g)
    }
    
    pub fn new_uncheck(p: &BigInt, q: &BigInt, g: &BigInt) -> Result<Self, CryptoError> {
        let (p_len, q_len, g_len) = (p.bits_len(), q.bits_len(), g.bits_len());
        if p_len == 0 || q_len == 0 || g_len == 0 || g_len > p_len {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "Invalid domain parameter size"));
        } 
        
        Ok(
            Self {
                p: p.deep_clone(),
                q: q.deep_clone(),
                g: g.deep_clone(),
            }
        )
    }
}

impl Display for DomainParameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let (p, q, g) = (format!("{:#x}", self.p), format!("{:#x}", self.q), format!("{:#x}", self.g));

        write!(f, "{{p: \"{}\", q: \"{}\", g: \"{}\"}}", p, q, g)
    }
}

impl Debug for DomainParameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl PublicKey {
    pub fn new_uncheck(dp: &DomainParameters, y: &BigInt) -> Result<PublicKey, CryptoError> {
        let y_len = y.bits_len();
        if y_len == 0 || y_len > dp.p.bits_len() {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "Invalid domain parameter size"));
        }
        
        Ok(
            PublicKey {
                dp: dp.clone(),
                y: y.deep_clone(),
            }
        )
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let dp = format!("{}", self.dp);
        let y = format!("{:#x}", self.y);
        write!(f, "{{y: \"{}\", dp: {}}}", y, dp)
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let dp = format!("{:?}", self.dp);
        let y = format!("{:#x}", self.y);
        write!(f, "{{y: \"{}\", dp: {}}}", y, dp)
    }
}

impl PrivateKey {
    pub fn new_uncheck(pk: &PublicKey, x: &BigInt) -> Result<PrivateKey, CryptoError> {
        if x.signnum() == None || x.signnum() == Some(-1) || x.signnum() == Some(0)
            || x >= &pk.dp.q {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter, "Invalid public key size"));
        }
        
        Ok(
            Self {
                pk: pk.clone(),
                x: x.deep_clone(),
            }
        )
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let pk = format!("{}", self.pk);
        let x = format!("{:#x}", self.x);
        write!(f, "{{x: \"{}\", {}}}", x, pk)
    }
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl PrivateKey {
    pub fn public_key(&self) -> &PublicKey {
        &self.pk
    }
    
    pub fn domain_parameters(&self) -> &DomainParameters {
        &self.public_key().domain_parameters()
    }
}

impl PublicKey {
    pub fn domain_parameters(&self) -> &DomainParameters {
        &self.dp
    }
}

pub struct KeyPair {
    pub_key: Option<PublicKey>,
    pri_key: Option<PrivateKey>,
}

impl From<PublicKey> for KeyPair {
    fn from(pk: PublicKey) -> Self {
        Self {
            pub_key: Some(pk),
            pri_key: None,
        }
    }
}

impl From<PrivateKey> for KeyPair {
    fn from(pk: PrivateKey) -> Self {
        Self {
            pub_key: None,
            pri_key: Some(pk),
        }
    }
}


impl KeyPair {
    pub fn public_key(&self) -> &PublicKey {
        if self.pri_key.is_some() {
            self.pri_key.as_ref().unwrap().public_key()
        } else {
            self.pub_key.as_ref().unwrap()
        }
    }
    
    pub fn domain_parameters(&self) -> &DomainParameters {
        &self.public_key().dp
    }
    
    pub fn private_key(&self) -> Option<&PrivateKey> {
        self.pri_key.as_ref()
    }
}

impl<H, R> Signature<SignatureContent> for DSA<H, R>
    where H: Digest, R: IterSource<u32> {
    type Output = ();

    fn sign(&mut self, signature: &mut SignatureContent, message: &[u8]) -> Result<Self::Output, CryptoError> {
        let (r, s) = self.sign_inner(message)?;
        signature.set(r, s);
        Ok(())
    }

    fn verify(&mut self, signature: &SignatureContent, message: &[u8]) -> Result<Self::Output, CryptoError> {
        let (r, s) = signature.to_bigint();
        self.verify_inner(message, &r, &s)
    }
}