use crate::elliptic::{EllipticCurve, KeyPair, PublicKey, PrivateKey, CurveParams};
use crate::{Digest, CryptoError, CryptoErrorKind, Signature};
use rmath::rand::IterSource;
use rmath::bigint::BigInt;
use crate::sha::SHA512;
use crate::ecdsa::csp_rng::CSPRng;
use crate::ecdsa::SignatureContent;

/// Elliptic Curve Digital Signature Algorithms  
/// FIPS 186-4, chapter 6
pub struct ECDSA<H, R, C> {
    curve: C,
    hf: H,
    rd: R,
    kp: KeyPair,
    md: SHA512,
    d_byes: Option<Vec<u8>>,
    hash_buf: Vec<u8>,
}

impl<H, R, C> ECDSA<H, R, C>
    where H: Clone + Digest {
    pub fn digest_func(&self) -> H {
        let mut h = self.hf.clone();
        h.reset();
        h
    }
}

impl<H, R, C> ECDSA<H, R, C> 
    where R: Clone + IterSource<u32> {
    pub fn rand_source(&self) -> R {
        self.rd.clone()
    }
}

impl<H, R, C> ECDSA<H, R, C>
    where C: EllipticCurve + Clone {
    pub fn curve(&self) -> C {
        self.curve.clone()
    }
}

impl<H, R, C> ECDSA<H, R, C> 
    where C: EllipticCurve {
    pub fn public_key(&self) -> &PublicKey {
        self.kp.public_key()
    }
    
    fn rand_field_element_inner(params: &CurveParams, buf: &[u8]) -> BigInt {
        let mut k = BigInt::from_be_bytes(buf);
        let n = params.base_point_order().clone() - BigInt::from(1u32);
        k.rem_euclid_assign(n);
        k += BigInt::from(1u32);
        k
    }
}

impl<H, R, C> ECDSA<H, R, C>
    where H: Digest, R: IterSource<u32>, C: EllipticCurve {
    fn rand_field_element(c: &C, rd: &mut R) -> Result<BigInt, CryptoError> {
        let params = c.curve_params();
        let b = (params.field_bits_size() >> 3) + 8;
        let mut buf = Vec::with_capacity(b);
        for e in rd.iter_mut() {
            buf.push(((e >> 24) & 0xff) as u8);
            buf.push(((e >> 16) & 0xff) as u8);
            buf.push(((e >> 8) & 0xff) as u8);
            buf.push((e & 0xff) as u8);
            if buf.len() >= b {
                break;
            }
        }
        buf.truncate(b);
        
        Ok(Self::rand_field_element_inner(params, buf.as_slice()))
    }
    
    fn rand_field_element_for_csprng(c: &C, csprng: &mut CSPRng) -> Result<BigInt, CryptoError> {
        let params = c.curve_params();
        let b = (params.field_bits_size() >> 3) + 8;
        let mut buf = Vec::with_capacity(b);
        csprng.read_full(&mut buf, b)?;
        
        Ok(Self::rand_field_element_inner(params, buf.as_slice()))
    }
    
    pub fn new_unchcek(hf: H, rd: R, curve: C, key_pair: KeyPair) -> Result<Self, CryptoError> {
        Ok(
            Self {
                hash_buf: Vec::with_capacity((hf.bits_len() + 7) >> 3),
                d_byes: key_pair.private_key().map(|e| {e.d.to_be_bytes()}),
                curve,
                hf,
                rd,
                kp: key_pair,
                md: SHA512::new(),
            }
        )
    }
    
    
    pub fn auto_generate_key(hf: H, mut rd: R, curve: C) -> Result<Self, CryptoError> {
        let k = Self::rand_field_element(&curve, &mut rd)?;
        let (px, py) = curve.scalar_base_point(k.as_ref());
        let pk = PrivateKey {
            pk: PublicKey {
                qx: px,
                qy: py,
            },
            d: k
        };
        Self::new_unchcek(hf, rd, curve, KeyPair::from(pk))
    }
    
    fn hash_to_bigint(&self, hash: &[u8]) -> BigInt {
        let order_bits = self.curve.curve_params().base_point_order().bits_len();
        let order_byte = (order_bits + 7) >> 3;
        let hash = if hash.len() > order_byte {
            &hash[..order_byte]
        } else {
            hash
        };
        
        let mut ret = BigInt::from_be_bytes(hash);
        let excess = (hash.len() << 3) - order_bits;
        if excess > 0 {
            ret >>= excess;
        }
        
        ret
    }
    
    fn fermat_inverse(k: &BigInt, n: &BigInt) -> BigInt {
        let two = BigInt::from(2u32);
        let nm2 = n.clone() - two;
        k.exp(&nm2, n)
    }
    
    fn sign_inner(&mut self) -> Result<(BigInt, BigInt), CryptoError> {
        let hash = self.hash_buf.as_slice();
        let pk = self.kp.private_key().ok_or(CryptoError::new(CryptoErrorKind::InvalidPrivateKey, "Public key cannot used to sign"))?;
        let d_bytes = self.d_byes.as_ref().unwrap();
        
        let entropy_len = std::cmp::min(32, (self.curve.curve_params().field_bits_size() + 7) >> 4);
        let mut entropy = Vec::with_capacity(entropy_len);
        
        for e in self.rd.iter_mut() {
            entropy.push(((e >> 24) & 0xff) as u8);
            entropy.push(((e >> 16) & 0xff) as u8);
            entropy.push(((e >> 8) & 0xff) as u8);
            entropy.push(( e & 0xff) as u8);
        }
        
        self.md.reset();
        self.md.write(d_bytes.as_slice());
        self.md.write(entropy.as_slice());
        self.md.write(hash);
        let mut key = entropy;
        self.md.checksum(&mut key);
        key.truncate(32);

        let aesiv = "IV for ECDSA CTR";
        let mut csprng = CSPRng::new(key, aesiv.as_bytes().to_vec())?;
        let n = self.curve.curve_params().base_point_order();
        if n.signnum() != Some(1) {
            return Err(CryptoError::new(CryptoErrorKind::InvalidPrivateKey, ""));
        }
        
        let (r, s) = loop {
            let (r, kinv) = loop {
                let k = Self::rand_field_element_for_csprng(&self.curve, &mut csprng)?;
                let kinv = Self::fermat_inverse(&k, n);
                let (mut r, _) = self.curve.scalar_base_point(k.as_ref());
                r.rem_euclid_assign(n.clone());
                if r.signnum() == Some(1) {
                    break (r, kinv);
                }
            };
            
            let e = self.hash_to_bigint(hash);
            let mut s = pk.d.clone() * r.clone();
            s += e;
            s *= kinv;
            s.rem_euclid_assign(n.clone());
            if s.signnum() == Some(1) {
                break (r, s);
            }
        };
        
        Ok((r, s))
    }
    
    fn verify_inner(&mut self, r: &BigInt, s: &BigInt) -> Result<(), CryptoError> {
        let hash = self.hash_buf.as_slice();
        let pk = self.kp.public_key();
        let c = self.curve.curve_params();
        let n = c.base_point_order();
        
        if r.signnum() != Some(1) || s.signnum() != Some(1) ||
            r >= n || s >= n {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, ""));
        }
        
        let mut e = self.hash_to_bigint(hash);
        let mut w = s.mod_inverse(n.clone());
        e *= w.clone();
        let mut u1 = e;
        u1.rem_euclid_assign(n.clone());
        w *= r.clone();
        let mut u2 = w;
        u2.rem_euclid_assign(n.clone());
        
        let (x1, y1) = c.scalar_base_point(u1.as_ref());
        let (x2, y2) = c.scalar(&pk.qx, &pk.qy, u2.as_ref());
        let (mut x, y) = c.add(&x1, &y1, &x2, &y2);
        
        if x.signnum() != Some(1) || y.signnum() != Some(1) {
            return Err(CryptoError::new(CryptoErrorKind::VerificationFailed, ""));
        }
        
        x.rem_euclid_assign(n.clone());
        if &x == r {
            Ok(())
        } else {
            Err(CryptoError::new(CryptoErrorKind::VerificationFailed, ""))
        }
    }
}

impl<H, R, C> Signature<SignatureContent> for ECDSA<H, R, C>
    where H: Digest, R: IterSource<u32>, C: EllipticCurve {
    type Output = ();

    fn sign(&mut self, signature: &mut SignatureContent, message: &[u8]) -> Result<Self::Output, CryptoError> {
        self.hf.reset();
        self.hf.write(message);
        self.hf.checksum(&mut self.hash_buf);
        let (r, s) = self.sign_inner()?;
        signature.set(r, s);
        Ok(())
    }

    fn verify(&mut self, signature: &SignatureContent, message: &[u8]) -> Result<Self::Output, CryptoError> {
        self.hf.reset();
        self.hf.write(message);
        self.hf.checksum(&mut self.hash_buf);
        let (r, s) = signature.to_bigint();
        self.verify_inner(&r, &s)?;
        Ok(())
    }
}