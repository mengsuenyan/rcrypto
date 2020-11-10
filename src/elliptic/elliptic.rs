use std::str::FromStr;
use rmath::bigint::{BigInt, Nat};
use rmath::rand::IterSource;
use crate::elliptic::key_pair::{PrivateKey, PublicKey};
use crate::{CryptoError, CryptoErrorKind};

/// CurveParams contains the parameters of an elliptic curve
pub struct CurveParams {
    // the order of the underlying field
    p: BigInt,
    // the order of the base point
    n: BigInt,
    // the constant coefficient of the curve equation
    b: BigInt,
    // (gx, gy) of the base point
    gx: BigInt,
    gy: BigInt,
    // the size of underlying field
    bit_size: usize,
    // the canonical name of the curve
    name: String,
}

/// A Curve represents a short-form Weierstrass curve with a=-3.  
/// (0, 0) identifies the infinite point. 
/// See https://www.hyperelliptic.org/EFD/g1p/auto-shortw.html
pub trait EllipticCurve {
    fn curve_params(&self) -> &CurveParams;
    
    /// reports whether the given (x,y) lies on the curve
    fn is_on_curve(&self, x: &BigInt, y: &BigInt) -> bool;
    
    /// (x1, y1) + (x2, y2)
    fn add(&self, x1: &BigInt, y1: &BigInt, x2: &BigInt, y2: &BigInt) -> (BigInt, BigInt);
    
    /// (x, y) * 2
    fn double(&self, x: &BigInt, y: &BigInt) -> (BigInt, BigInt);
    
    /// (x, y) * k
    fn scalar(&self, x: &BigInt, y: &BigInt, k: &Nat) -> (BigInt, BigInt);
    
    /// base point (gx, gy) * k -> (zx, zy)
    fn scalar_base_point(&self, k: &Nat) -> (BigInt, BigInt);
}

impl EllipticCurve for CurveParams {
    fn curve_params(&self) -> &CurveParams {
        self
    }

    fn is_on_curve(&self, x: &BigInt, y: &BigInt) -> bool {
        if x.is_nan() || y.is_nan() {
            return false;
        }
        // y² = x³ - 3x + b
        let (mut x3, mut y2) = (x.sqr(), y.sqr());
        y2.rem_euclid_assign(self.p.clone());
        x3 *= x.clone();
        
        let mut three_x = x.clone() << 1;
        three_x += x.clone();
        
        x3 -= three_x;
        x3 += self.b.clone();
        x3.rem_euclid_assign(self.p.clone());
        
        x3 == y2
    }

    fn add(&self, x1: &BigInt, y1: &BigInt, x2: &BigInt, y2: &BigInt) -> (BigInt, BigInt) {
        if x1.is_nan() || y1.is_nan() || x2.is_nan() || y2.is_nan() {
            let tmp = Vec::new();
            return (BigInt::from_be_bytes(tmp.as_slice()), BigInt::from_be_bytes(tmp.as_slice()));
        }
        
        let (z1, z2) = (Self::z_for_affine(x1, y1), Self::z_for_affine(x2, y2));
        let (x, y, z) = self.add_jacobian(x1, y1, &z1, x2, y2, &z2);
        self.affine_from_jacobian(&x, &y, &z)
    }

    fn double(&self, x: &BigInt, y: &BigInt) -> (BigInt, BigInt) {
        if x.is_nan() || y.is_nan() {
            let tmp = Vec::new();
            return (BigInt::from_be_bytes(tmp.as_slice()), BigInt::from_be_bytes(tmp.as_slice()));
        }
        
        let z1 = Self::z_for_affine(x, y);
        let (x, y, z) = self.double_jacobian(x, y, &z1);
        self.affine_from_jacobian(&x, &y, &z)
    }

    fn scalar(&self, x: &BigInt, y: &BigInt, k: &Nat) -> (BigInt, BigInt) {
        if x.is_nan() || y.is_nan() || k.is_nan() {
            let tmp = Vec::new();
            return (BigInt::from_be_bytes(tmp.as_slice()), BigInt::from_be_bytes(tmp.as_slice()));
        }
        
        let k = k.to_be_bytes();
        self.scalar_inner(x, y, k.as_slice())
    }

    fn scalar_base_point(&self, k: &Nat) -> (BigInt, BigInt) {
        if k.is_nan() {
            let tmp = Vec::new();
            return (BigInt::from_be_bytes(tmp.as_slice()), BigInt::from_be_bytes(tmp.as_slice()));
        }
        
        self.scalar(&self.gx, &self.gy, k)
    }
}

impl CurveParams {
    pub(crate) fn field_order(&self) -> &BigInt {
        &self.p
    }
    
    pub(crate) fn base_point_order(&self) -> &BigInt {
        &self.n
    }
    
    pub fn field_bits_size(&self) -> usize {
        self.bit_size
    }
    
    pub(crate) fn base_point(&self) -> (&BigInt, &BigInt) {
        (&self.gx, &self.gy)
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
    
    pub(crate) fn coefficient_b(&self) -> &BigInt {
        &self.b
    }
    
    pub fn generate_key<R: IterSource<u32>>(&self, rd: &mut R) -> Result<PrivateKey, CryptoError> {
        const MASK: [u8;8] = [0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f];
        let bits_len = self.n.bits_len();
        let b_len = (bits_len + 7) >> 3;
        let mut priv_key = Vec::with_capacity((b_len + 3) >> 2);
        
        loop {
            priv_key.clear();
            rd.iter_mut().take((b_len + 3) >> 2).for_each(|x| {
                priv_key.push(((x >> 24) & 0xff) as u8);
                priv_key.push(((x >> 16) & 0xff) as u8);
                priv_key.push(((x >> 8) & 0xff) as u8);
                priv_key.push((x & 0xff) as u8);
            });
            priv_key.truncate(b_len);

            // We have to mask off any excess bits in the case that the size of the
            // underlying field is not a whole number of bytes.
            priv_key[0] &= MASK[bits_len & 7];
            // This is because, in tests, rand will return all zeros and we don't
            // want to get the point at infinity and loop forever.
            priv_key[1] ^= 0x42;

            // If the scalar is out of range, sample another random number.
            let key = BigInt::from_be_bytes(priv_key.as_slice());
            if key < self.n {
                let (qx, qy) = self.scalar_inner(&self.gx, &self.gy, priv_key.as_slice());
                if !qx.is_nan() && !qy.is_nan() {
                    return Ok(
                        PrivateKey {
                            pk: PublicKey {
                                qx,
                                qy,
                            },
                            d: key,
                        }
                    )
                }
            }
        }
    }

    fn scalar_inner(&self, x: &BigInt, y: &BigInt, k: &[u8]) -> (BigInt, BigInt) {
        let z = BigInt::from(1u32);
        let (mut bx, mut by, mut bz) = (BigInt::from(0u32), BigInt::from(0u32), BigInt::from(0u32));
        for &e in k.iter() {
            let mut byte = e;
            for _ in 0..8 {
                let (tmp_x, tmp_y, tmp_z) = self.double_jacobian(&bx, &by, &bz);
                bx = tmp_x; by = tmp_y; bz = tmp_z;
                if (byte & 0x80) == 0x80 {
                    let (tmp_x, tmp_y, tmp_z) = self.add_jacobian(x, y, &z, &bx, &by, &bz);
                    bx = tmp_x; by = tmp_y; bz = tmp_z;
                }

                byte <<= 1;
            }
        }

        self.affine_from_jacobian(&bx, &by, &bz)
    }

    /// compute a jacobian z value for the affine point `self`. If x and
    /// y are zero, it assumes that they represent the point at infinity because (0,
    /// 0) is not on the any of the curves handled here.
    fn z_for_affine(x: &BigInt, y: &BigInt) -> BigInt {
        debug_assert!(!x.is_nan() && !y.is_nan());
        
        if x.signnum() != Some(0) || y.signnum() != Some(0) {
            BigInt::from(1u32)
        } else {
            BigInt::from(0u32)
        }
    }
    
    /// Jacobian transform.
    fn affine_from_jacobian(&self, x: &BigInt, y: &BigInt, z: &BigInt) -> (BigInt, BigInt) {
        debug_assert!(!x.is_nan() && !y.is_nan() && !z.is_nan());
        
        if z.signnum() == Some(0) {
            (BigInt::from(0u32), BigInt::from(0u32))
        } else {
            let zinv = z.mod_inverse(self.p.clone());
            let mut zinvsq = zinv.sqr();
            let mut xout = x.clone() * zinvsq.clone();
            xout.rem_euclid_assign(self.p.clone());
            zinvsq *= zinv;
            let mut yout = y.clone() * zinvsq;
            yout.rem_euclid_assign(self.p.clone());
            (xout, yout)
        }
    }
    
    fn add_jacobian(&self, x1: &BigInt, y1: &BigInt, z1: &BigInt, x2: &BigInt, y2: &BigInt, z2: &BigInt) -> (BigInt, BigInt, BigInt) {
        // See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
        if z1.signnum() == Some(0) {
            return (x2.deep_clone(), y2.deep_clone(), z2.deep_clone());
        } else if z2.signnum() == Some(0) {
            return (x1.deep_clone(), y1.deep_clone(), z1.deep_clone());
        }

        let (mut z1z1, mut z2z2) = (z1.sqr(), z2.sqr());
        z1z1.rem_euclid_assign(self.p.clone());
        z2z2.rem_euclid_assign(self.p.clone());

        let (mut u1, mut u2) = (x1.clone() * z2z2.clone(), x2.clone() * z1z1.clone());
        u1.rem_euclid_assign(self.p.clone());
        u2.rem_euclid_assign(self.p.clone());
        u2 -= u1.clone();
        let mut h = u2;
        
        let x_equal = h.signnum() == Some(0);
        if h.signnum() == Some(-1) {
            h += self.p.clone();
        }
        let i = h.clone() << 1;
        let i = i.sqr();
        let j = h.clone() * i.clone();

        let (mut s1, mut s2) = (y1.clone() * z2.clone(), y2.clone() * z1.clone());
        s1 *= z2z2.clone();
        s1.rem_euclid_assign(self.p.clone());
        s2 *= z1z1.clone();
        s2.rem_euclid_assign(self.p.clone());
        let mut r = s2.clone() - s1.clone();
        if r.signnum() == Some(-1) {
            r += self.p.clone();
        }
        let y_equal = r.signnum() == Some(0);
        if x_equal && y_equal {
            return self.double_jacobian(x1, y1, z1);
        }
        
        r <<= 1;
        let mut v = u1.clone() * i.clone();

        let mut x3 = r.sqr();
        x3 -= j.clone();
        x3 -= v.clone();
        x3 -= v.clone();
        x3.rem_euclid_assign(self.p.clone());

        v -= x3.clone();
        let mut y3 = r.clone() * v.clone();
        s1 *= j.clone();
        s1 <<= 1;
        y3 -= s1.clone();
        y3.rem_euclid_assign(self.p.clone());

        let z3 = z1.clone() + z2.clone();
        let mut z3 = z3.sqr();
        z3 -= z1z1.clone();
        z3 -= z2z2.clone();
        z3 *= h.clone();
        z3.rem_euclid_assign(self.p.clone());

        (x3, y3, z3)
    }
    
    
    fn double_jacobian(&self, x: &BigInt, y: &BigInt, z: &BigInt) -> (BigInt, BigInt, BigInt) {
        // See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
        let (mut delta, mut gamma) = (z.sqr(), y.sqr());
        delta.rem_euclid_assign(self.p.clone());
        gamma.rem_euclid_assign(self.p.clone());
        let (mut alpha, mut alpha2) = (x.clone() - delta.clone(), x.clone() + delta.clone());
        if alpha.signnum() == Some(-1) {
            alpha += self.p.clone();
        }
        alpha *= alpha2.clone();
        alpha2 = alpha.deep_clone();
        alpha <<= 1;
        alpha += alpha2.clone();

        let mut beta = x.clone() * gamma.clone();

        let mut x3 = alpha.sqr();
        let mut beta8 = beta.clone() << 3;
        beta8.rem_euclid_assign(self.p.clone());
        x3 -= beta8;
        if x3.signnum() == Some(-1) {
            x3 += self.p.clone();
        }
        x3.rem_euclid_assign(self.p.clone());

        let z3 = y.clone() + z.clone();
        let mut z3 = z3.sqr();
        z3 -= gamma.clone();
        if z3.signnum() == Some(-1) {
            z3 += self.p.clone();
        }
        z3 -= delta.clone();
        if z3.signnum() == Some(-1) {
            z3 += self.p.clone();
        }
        z3.rem_euclid_assign(self.p.clone());

        beta <<= 2;
        beta -= x3.clone();
        if beta.signnum() == Some(-1) {
            beta += self.p.clone();
        }
        let mut y3 = alpha.clone() * beta.clone();

        let mut gamma = gamma.sqr();
        gamma <<= 3;
        gamma.rem_euclid_assign(self.p.clone());

        y3 -= gamma.clone();
        if y3.signnum() == Some(-1) {
            y3 += self.p.clone();
        }
        y3.rem_euclid_assign(self.p.clone());

        (x3, y3, z3)
    }

    /// FIPS 186-4, D.1.2.3 P-224 Curve  
    /// GF(p), E: $y^2 \equiv x^3 - 3\cdot x + b \mod p$  
    /// p.bits_len() = 224
    pub fn p224() -> Result<CurveParams, CryptoError> {
        let p = BigInt::from_str("26959946667150639794667015087019630673557916260026308143510066298881")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let n = BigInt::from_str("26959946667150639794667015087019625940457807714424391721682722368061")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let b = BigInt::from_str("0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let gx = BigInt::from_str("0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let gy = BigInt::from_str("0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let bit_size = 224;
        let name = String::from("P-224");

         Ok(
             CurveParams {
                 p,
                 n,
                 b,
                 gx,
                 gy,
                 bit_size,
                 name,
             }
         )
    }

    /// FIPS 186-4, D.1.2.4 P-256 Curve  
    /// GF(p), E: $y^2 \equiv x^3 - 3\cdot x + b \mod p$  
    /// p.bits_len() = 256
    pub fn p256() -> Result<CurveParams, CryptoError> {
        let p = BigInt::from_str("115792089210356248762697446949407573530086143415290314195533631308867097853951")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let n = BigInt::from_str("115792089210356248762697446949407573529996955224135760342422259061068512044369")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let b = BigInt::from_str("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let gx = BigInt::from_str("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let gy = BigInt::from_str("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let bit_size = 256;
        let name = String::from("P-256");

        Ok(
            CurveParams {
                p,
                n,
                b,
                gx,
                gy,
                bit_size,
                name,
            }
        )
    }

    /// FIPS 186-4, D.1.2.4 P-384 Curve  
    /// GF(p), E: $y^2 \equiv x^3 - 3\cdot x + b \mod p$  
    /// p.bits_len() = 384
    pub fn p384() -> Result<CurveParams, CryptoError> {
        let p = BigInt::from_str("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let n = BigInt::from_str("39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let b = BigInt::from_str("0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let gx = BigInt::from_str("0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let gy = BigInt::from_str("0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let bit_size = 384;
        let name = String::from("P-384");

        Ok(
            CurveParams {
                p,
                n,
                b,
                gx,
                gy,
                bit_size,
                name,
            }
        )
    }

    /// FIPS 186-4, D.1.2.5 P-512 Curve  
    /// GF(p), E: $y^2 \equiv x^3 - 3\cdot x + b \mod p$
    /// p.bits_len() = 521
    pub fn p521() -> Result<CurveParams, CryptoError>{
        let p = BigInt::from_str("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let n = BigInt::from_str("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let b = BigInt::from_str("0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let gx = BigInt::from_str("0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let gy = BigInt::from_str("0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        let bit_size = 512;
        let name = String::from("P-512");

        Ok(
            CurveParams {
                p,
                n,
                b,
                gx,
                gy,
                bit_size,
                name,
            }
        )
    }
}

impl Clone for CurveParams {
    fn clone(&self) -> Self {
        Self {
            p: self.p.deep_clone(),
            n: self.n.deep_clone(),
            b: self.b.deep_clone(),
            gx: self.gx.deep_clone(),
            gy: self.gy.deep_clone(),
            bit_size: self.bit_size,
            name: self.name.clone(),
        }
    }
}