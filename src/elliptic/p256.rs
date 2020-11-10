//! this file convert from golang source code
//! 
//! This is a constant-time, 32-bit implementation of P224. See FIPS 186-4, 
//! section D.2.3.

use std::str::FromStr;
use crate::elliptic::{CurveParams, EllipticCurve};
use rmath::bigint::{BigInt, Nat};
use crate::{CryptoError, CryptoErrorKind};


/// Field elements are represented as nine, unsigned 32-bit words.
///
/// The value of a field element is:
///   x[0] + (x[1] * 2**29) + (x[2] * 2**57) + ... + (x[8] * 2**228)
///
/// That is, each limb is alternately 29 or 28-bits wide in little-endian
/// order.
///
/// This means that a field element hits 2**257, rather than 2**256 as we would
/// like. A 28, 29, ... pattern would cause us to hit 2**256, but that causes
/// problems when multiplying as terms end up one bit short of a limb which
/// would require much bit-shifting to correct.
///
/// Finally, the values stored in a field element are in Montgomery form. So the
/// value |y| is stored as (y*R) mod p, where p is the P-256 prime and R is
/// 2**257.
const P256_LIMBS: usize = 9;
const BOTTOM_29BITS: u32 = 0x1fffffff;
const BOTTOM_28BITS: u32 = 0xfffffff;

/// p256One is the number 1 as a field element.
const P256_ONE: [u32; P256_LIMBS] = [2, 0, 0, 0xffff800, 0x1fffffff, 0xfffffff, 0x1fbfffff, 0x1ffffff, 0];
// const P256_ZERO: [u32; P256_LIMBS] = [0, 0, 0, 0, 0, 0, 0, 0, 0];
// p256P is the prime modulus as a field element.
// const P256_P: [u32; P256_LIMBS] = [0x1fffffff, 0xfffffff, 0x1fffffff, 0x3ff, 0, 0, 0x200000, 0xf000000, 0xfffffff];
// p2562P is the twice prime modulus as a field element.
// const p256_2P: [u32; P256_LIMBS] = [0x1ffffffe, 0xfffffff, 0x1fffffff, 0x7ff, 0, 0, 0x400000, 0xe000000, 0x1fffffff];

/// p256Precomputed contains precomputed values to aid the calculation of scalar
/// multiples of the base point, G. It's actually two, equal length, tables
/// concatenated.
///
/// The first table contains (x,y) field element pairs for 16 multiples of the
/// base point, G.
///
///   Index  |  Index (binary) | Value
///       0  |           0000  | 0G (all zeros, omitted)
///       1  |           0001  | G
///       2  |           0010  | 2**64G
///       3  |           0011  | 2**64G + G
///       4  |           0100  | 2**128G
///       5  |           0101  | 2**128G + G
///       6  |           0110  | 2**128G + 2**64G
///       7  |           0111  | 2**128G + 2**64G + G
///       8  |           1000  | 2**192G
///       9  |           1001  | 2**192G + G
///      10  |           1010  | 2**192G + 2**64G
///      11  |           1011  | 2**192G + 2**64G + G
///      12  |           1100  | 2**192G + 2**128G
///      13  |           1101  | 2**192G + 2**128G + G
///      14  |           1110  | 2**192G + 2**128G + 2**64G
///      15  |           1111  | 2**192G + 2**128G + 2**64G + G
///
/// The second table follows the same style, but the terms are 2**32G,
/// 2**96G, 2**160G, 2**224G.
///
/// This is ~2KB of data.
const P256_PRECOMPUTED: [u32; P256_LIMBS * 2 * 15 *2] = [
    0x11522878, 0xe730d41, 0xdb60179, 0x4afe2ff, 0x12883add, 0xcaddd88, 0x119e7edc, 0xd4a6eab, 0x3120bee,
    0x1d2aac15, 0xf25357c, 0x19e45cdd, 0x5c721d0, 0x1992c5a5, 0xa237487, 0x154ba21, 0x14b10bb, 0xae3fe3,
    0xd41a576, 0x922fc51, 0x234994f, 0x60b60d3, 0x164586ae, 0xce95f18, 0x1fe49073, 0x3fa36cc, 0x5ebcd2c,
    0xb402f2f, 0x15c70bf, 0x1561925c, 0x5a26704, 0xda91e90, 0xcdc1c7f, 0x1ea12446, 0xe1ade1e, 0xec91f22,
    0x26f7778, 0x566847e, 0xa0bec9e, 0x234f453, 0x1a31f21a, 0xd85e75c, 0x56c7109, 0xa267a00, 0xb57c050,
    0x98fb57, 0xaa837cc, 0x60c0792, 0xcfa5e19, 0x61bab9e, 0x589e39b, 0xa324c5, 0x7d6dee7, 0x2976e4b,
    0x1fc4124a, 0xa8c244b, 0x1ce86762, 0xcd61c7e, 0x1831c8e0, 0x75774e1, 0x1d96a5a9, 0x843a649, 0xc3ab0fa,
    0x6e2e7d5, 0x7673a2a, 0x178b65e8, 0x4003e9b, 0x1a1f11c2, 0x7816ea, 0xf643e11, 0x58c43df, 0xf423fc2,
    0x19633ffa, 0x891f2b2, 0x123c231c, 0x46add8c, 0x54700dd, 0x59e2b17, 0x172db40f, 0x83e277d, 0xb0dd609,
    0xfd1da12, 0x35c6e52, 0x19ede20c, 0xd19e0c0, 0x97d0f40, 0xb015b19, 0x449e3f5, 0xe10c9e, 0x33ab581,
    0x56a67ab, 0x577734d, 0x1dddc062, 0xc57b10d, 0x149b39d, 0x26a9e7b, 0xc35df9f, 0x48764cd, 0x76dbcca,
    0xca4b366, 0xe9303ab, 0x1a7480e7, 0x57e9e81, 0x1e13eb50, 0xf466cf3, 0x6f16b20, 0x4ba3173, 0xc168c33,
    0x15cb5439, 0x6a38e11, 0x73658bd, 0xb29564f, 0x3f6dc5b, 0x53b97e, 0x1322c4c0, 0x65dd7ff, 0x3a1e4f6,
    0x14e614aa, 0x9246317, 0x1bc83aca, 0xad97eed, 0xd38ce4a, 0xf82b006, 0x341f077, 0xa6add89, 0x4894acd,
    0x9f162d5, 0xf8410ef, 0x1b266a56, 0xd7f223, 0x3e0cb92, 0xe39b672, 0x6a2901a, 0x69a8556, 0x7e7c0,
    0x9b7d8d3, 0x309a80, 0x1ad05f7f, 0xc2fb5dd, 0xcbfd41d, 0x9ceb638, 0x1051825c, 0xda0cf5b, 0x812e881,
    0x6f35669, 0x6a56f2c, 0x1df8d184, 0x345820, 0x1477d477, 0x1645db1, 0xbe80c51, 0xc22be3e, 0xe35e65a,
    0x1aeb7aa0, 0xc375315, 0xf67bc99, 0x7fdd7b9, 0x191fc1be, 0x61235d, 0x2c184e9, 0x1c5a839, 0x47a1e26,
    0xb7cb456, 0x93e225d, 0x14f3c6ed, 0xccc1ac9, 0x17fe37f3, 0x4988989, 0x1a90c502, 0x2f32042, 0xa17769b,
    0xafd8c7c, 0x8191c6e, 0x1dcdb237, 0x16200c0, 0x107b32a1, 0x66c08db, 0x10d06a02, 0x3fc93, 0x5620023,
    0x16722b27, 0x68b5c59, 0x270fcfc, 0xfad0ecc, 0xe5de1c2, 0xeab466b, 0x2fc513c, 0x407f75c, 0xbaab133,
    0x9705fe9, 0xb88b8e7, 0x734c993, 0x1e1ff8f, 0x19156970, 0xabd0f00, 0x10469ea7, 0x3293ac0, 0xcdc98aa,
    0x1d843fd, 0xe14bfe8, 0x15be825f, 0x8b5212, 0xeb3fb67, 0x81cbd29, 0xbc62f16, 0x2b6fcc7, 0xf5a4e29,
    0x13560b66, 0xc0b6ac2, 0x51ae690, 0xd41e271, 0xf3e9bd4, 0x1d70aab, 0x1029f72, 0x73e1c35, 0xee70fbc,
    0xad81baf, 0x9ecc49a, 0x86c741e, 0xfe6be30, 0x176752e7, 0x23d416, 0x1f83de85, 0x27de188, 0x66f70b8,
    0x181cd51f, 0x96b6e4c, 0x188f2335, 0xa5df759, 0x17a77eb6, 0xfeb0e73, 0x154ae914, 0x2f3ec51, 0x3826b59,
    0xb91f17d, 0x1c72949, 0x1362bf0a, 0xe23fddf, 0xa5614b0, 0xf7d8f, 0x79061, 0x823d9d2, 0x8213f39,
    0x1128ae0b, 0xd095d05, 0xb85c0c2, 0x1ecb2ef, 0x24ddc84, 0xe35e901, 0x18411a4a, 0xf5ddc3d, 0x3786689,
    0x52260e8, 0x5ae3564, 0x542b10d, 0x8d93a45, 0x19952aa4, 0x996cc41, 0x1051a729, 0x4be3499, 0x52b23aa,
    0x109f307e, 0x6f5b6bb, 0x1f84e1e7, 0x77a0cfa, 0x10c4df3f, 0x25a02ea, 0xb048035, 0xe31de66, 0xc6ecaa3,
    0x28ea335, 0x2886024, 0x1372f020, 0xf55d35, 0x15e4684c, 0xf2a9e17, 0x1a4a7529, 0xcb7beb1, 0xb2a78a1,
    0x1ab21f1f, 0x6361ccf, 0x6c9179d, 0xb135627, 0x1267b974, 0x4408bad, 0x1cbff658, 0xe3d6511, 0xc7d76f,
    0x1cc7a69, 0xe7ee31b, 0x54fab4f, 0x2b914f, 0x1ad27a30, 0xcd3579e, 0xc50124c, 0x50daa90, 0xb13f72,
    0xb06aa75, 0x70f5cc6, 0x1649e5aa, 0x84a5312, 0x329043c, 0x41c4011, 0x13d32411, 0xb04a838, 0xd760d2d,
    0x1713b532, 0xbaa0c03, 0x84022ab, 0x6bcf5c1, 0x2f45379, 0x18ae070, 0x18c9e11e, 0x20bca9a, 0x66f496b,
    0x3eef294, 0x67500d2, 0xd7f613c, 0x2dbbeb, 0xb741038, 0xe04133f, 0x1582968d, 0xbe985f7, 0x1acbc1a,
    0x1a6a939f, 0x33e50f6, 0xd665ed4, 0xb4b7bd6, 0x1e5a3799, 0x6b33847, 0x17fa56ff, 0x65ef930, 0x21dc4a,
    0x2b37659, 0x450fe17, 0xb357b65, 0xdf5efac, 0x15397bef, 0x9d35a7f, 0x112ac15f, 0x624e62e, 0xa90ae2f,
    0x107eecd2, 0x1f69bbe, 0x77d6bce, 0x5741394, 0x13c684fc, 0x950c910, 0x725522b, 0xdc78583, 0x40eeabb,
    0x1fde328a, 0xbd61d96, 0xd28c387, 0x9e77d89, 0x12550c40, 0x759cb7d, 0x367ef34, 0xae2a960, 0x91b8bdc,
    0x93462a9, 0xf469ef, 0xb2e9aef, 0xd2ca771, 0x54e1f42, 0x7aaa49, 0x6316abb, 0x2413c8e, 0x5425bf9,
    0x1bed3e3a, 0xf272274, 0x1f5e7326, 0x6416517, 0xea27072, 0x9cedea7, 0x6e7633, 0x7c91952, 0xd806dce,
    0x8e2a7e1, 0xe421e1a, 0x418c9e1, 0x1dbc890, 0x1b395c36, 0xa1dc175, 0x1dc4ef73, 0x8956f34, 0xe4b5cf2,
    0x1b0d3a18, 0x3194a36, 0x6c2641f, 0xe44124c, 0xa2f4eaa, 0xa8c25ba, 0xf927ed7, 0x627b614, 0x7371cca,
    0xba16694, 0x417bc03, 0x7c0a7e3, 0x9c35c19, 0x1168a205, 0x8b6b00d, 0x10e3edc9, 0x9c19bf2, 0x5882229,
    0x1b2b4162, 0xa5cef1a, 0x1543622b, 0x9bd433e, 0x364e04d, 0x7480792, 0x5c9b5b3, 0xe85ff25, 0x408ef57,
    0x1814cfa4, 0x121b41b, 0xd248a0f, 0x3b05222, 0x39bb16a, 0xc75966d, 0xa038113, 0xa4a1769, 0x11fbc6c,
    0x917e50e, 0xeec3da8, 0x169d6eac, 0x10c1699, 0xa416153, 0xf724912, 0x15cd60b7, 0x4acbad9, 0x5efc5fa,
    0xf150ed7, 0x122b51, 0x1104b40a, 0xcb7f442, 0xfbb28ff, 0x6ac53ca, 0x196142cc, 0x7bf0fa9, 0x957651,
    0x4e0f215, 0xed439f8, 0x3f46bd5, 0x5ace82f, 0x110916b6, 0x6db078, 0xffd7d57, 0xf2ecaac, 0xca86dec,
    0x15d6b2da, 0x965ecc9, 0x1c92b4c2, 0x1f3811, 0x1cb080f5, 0x2d8b804, 0x19d1c12d, 0xf20bd46, 0x1951fa7,
    0xa3656c3, 0x523a425, 0xfcd0692, 0xd44ddc8, 0x131f0f5b, 0xaf80e4a, 0xcd9fc74, 0x99bb618, 0x2db944c,
    0xa673090, 0x1c210e1, 0x178c8d23, 0x1474383, 0x10b8743d, 0x985a55b, 0x2e74779, 0x576138, 0x9587927,
    0x133130fa, 0xbe05516, 0x9f4d619, 0xbb62570, 0x99ec591, 0xd9468fe, 0x1d07782d, 0xfc72e0b, 0x701b298,
    0x1863863b, 0x85954b8, 0x121a0c36, 0x9e7fedf, 0xf64b429, 0x9b9d71e, 0x14e2f5d8, 0xf858d3a, 0x942eea8,
    0xda5b765, 0x6edafff, 0xa9d18cc, 0xc65e4ba, 0x1c747e86, 0xe4ea915, 0x1981d7a1, 0x8395659, 0x52ed4e2,
    0x87d43b7, 0x37ab11b, 0x19d292ce, 0xf8d4692, 0x18c3053f, 0x8863e13, 0x4c146c0, 0x6bdf55a, 0x4e4457d,
    0x16152289, 0xac78ec2, 0x1a59c5a2, 0x2028b97, 0x71c2d01, 0x295851f, 0x404747b, 0x878558d, 0x7d29aa4,
    0x13d8341f, 0x8daefd7, 0x139c972d, 0x6b7ea75, 0xd4a9dde, 0xff163d8, 0x81d55d7, 0xa5bef68, 0xb7b30d8,
    0xbe73d6f, 0xaa88141, 0xd976c81, 0x7e7a9cc, 0x18beb771, 0xd773cbd, 0x13f51951, 0x9d0c177, 0x1c49a78,
];

const TWO30M2: u32 = (1u32<<30) - (1u32<<2);
const TWO30P13M2: u32 = (1u32<<30) + (1u32<<13) - (1u32<<2);
const TWO31M2: u32 = (1u32<<31) - (1u32<<2);
const TWO31P24M2: u32 = (1u32<<31) + (1u32<<24) - (1u32<<2);
const TWO30M27M2: u32 = (1u32<<30) - (1u32<<27) - (1u32<<2);
const TWO31M3: u32 = (1u32<<31) - (1u32<<3);

// p256Zero31 is 0 mod p.
const P256ZERO31: [u32; P256_LIMBS] = [TWO31M3, TWO30M2, TWO31M2, TWO30P13M2, TWO31M2, TWO30M2, TWO31P24M2, TWO30M27M2, TWO31M2];

type P256FEle = [u32; P256_LIMBS];

pub struct CurveP256 {
    cp: CurveParams,

    // RInverse contains 1/R mod p - the inverse of the Montgomery constant
    // (2**257).
    r_inv: BigInt,
}

impl Clone for CurveP256 {
    fn clone(&self) -> Self {
        Self {
            cp: self.cp.clone(),
            r_inv: self.r_inv.deep_clone(),
        }
    }
}

impl CurveP256 {
    pub fn new() -> Result<Self, CryptoError> {
        let cp = CurveParams::p256()?;
        let r_inv = BigInt::from_str("0x7fffffff00000001fffffffe8000000100000000ffffffff0000000180000000")
            .or_else(|e| {Err(CryptoError::new(CryptoErrorKind::InnerErr, e))})?;
        
        Ok(
            Self {
                cp,
                r_inv,
            }
        )
    }
    
    /// p256GetScalar endian-swaps the big-endian scalar value from in and writes it
    /// to out. If the scalar is equal or greater than the order of the group, it's
    /// reduced modulo that order.
    fn p256_get_scalar(&self, out: &mut [u8;32], n: &Nat) {
        
        let a = if n >= self.cp.base_point_order().as_ref() {
            let tmp = n.clone() % self.cp.base_point_order().as_ref().clone();
            tmp.to_be_bytes()
        } else{
            n.to_be_bytes()
        };
        out.iter_mut().take(a.len()).rev().zip(a.iter()).for_each(|(x, &y)| {
            *x = y;
        });
    }

    /// Field element operations:
    /// 
    /// non_zero_to_all_ones returns:
    ///   0xffffffff for 0 < x <= 2**31
    ///   0 for x == 0 or x > 2**31.
    fn non_zero_to_all_ones(x: u32) -> u32 {
        (x.wrapping_sub(1) >> 31).wrapping_sub(1)
    }

    /// p256_reduce_carry adds a multiple of p in order to cancel |carry|,
    /// which is a term at 2**257.
    ///
    /// On entry: carry < 2**3, inout[0,2,...] < 2**29, inout[1,3,...] < 2**28.
    /// On exit: inout[0,2,..] < 2**30, inout[1,3,...] < 2**29.
    fn p256_reduce_carry(inout: &mut P256FEle, carry: u32) {
        let carry_mask = Self::non_zero_to_all_ones(carry);

        inout[0] = inout[0].wrapping_add(carry << 1);
        inout[3] = inout[3].wrapping_add(0x10000000 & carry_mask);
        // carry < 2**3 thus (carry << 11) < 2**14 and we added 2**28 in the
        // previous line therefore this doesn't underflow.
        inout[3] = inout[3].wrapping_sub(carry << 11);
        inout[4] = inout[4].wrapping_add((0x20000000 - 1) & carry_mask);
        inout[5] = inout[5].wrapping_add((0x10000000 - 1) & carry_mask);
        inout[6] = inout[6].wrapping_add((0x20000000 - 1) & carry_mask);
        inout[6] = inout[6].wrapping_sub(carry << 22);
        // This may underflow if carry is non-zero but, if so, we'll fix it in the
        // next line.
        inout[7] = inout[7].wrapping_sub(1 & carry_mask);
        inout[7] = inout[7].wrapping_add(carry << 25);
    }
    
    fn p256_sum_a(out: *mut P256FEle, a: *const P256FEle, b: *const P256FEle) {
        let (out, a, b) = unsafe {
            (&mut *out, &*a, &*b)
        };
        Self::p256_sum(out, a, b);
    }
    
    fn p256_sum(out: &mut P256FEle, a: &P256FEle, b: &P256FEle) {
        let (mut carry, mut i) = (0u32, 0usize);
        loop {
            out[i] = a[i].wrapping_add(b[i]);
            out[i] = out[i].wrapping_add(carry);
            carry = out[i] >> 29;
            out[i] &= BOTTOM_29BITS;
            i += 1;
            if i == P256_LIMBS {
                break;
            }

            out[i] = a[i].wrapping_add(b[i]);
            out[i] = out[i].wrapping_add(carry);
            carry = out[i] >> 28;
            out[i] &= BOTTOM_28BITS;
            i += 1;
        }
        
        Self::p256_reduce_carry(out, carry);
    }
    
    fn p256_diff_a(out: *mut P256FEle, a: *const P256FEle, b: *const P256FEle) {
        let (out, a, b) = unsafe {
            (&mut *out, &*a, &*b)
        };
        Self::p256_diff(out, a, b);
    }

    /// p256Diff sets out = in-in2.
    ///
    /// On entry: in[0,2,...] < 2**30, in[1,3,...] < 2**29 and
    ///           in2[0,2,...] < 2**30, in2[1,3,...] < 2**29.
    /// On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
    fn p256_diff(out: &mut P256FEle, a: &P256FEle, b: &P256FEle) {
        let (mut carry, mut i) = (0u32, 0usize);
        
        loop {
            out[i] = a[i].wrapping_sub(b[i]);
            out[i] = out[i].wrapping_add(P256ZERO31[i]);
            out[i] = out[i].wrapping_add(carry);
            carry = out[i] >> 29;
            out[i] &= BOTTOM_29BITS;

            i += 1;
            if i == P256_LIMBS {
                break;
            }

            out[i] = a[i].wrapping_sub(b[i]);
            out[i] = out[i].wrapping_add(P256ZERO31[i]);
            out[i] = out[i].wrapping_add(carry);
            carry = out[i] >> 28;
            out[i] &= BOTTOM_28BITS;
            i += 1;
        }
        
        Self::p256_reduce_carry(out, carry);
    }
    
    #[inline]
    fn uint32(n: u64) -> u32 {
        (n & 0xffffffff) as u32
    }

    /// p256ReduceDegree sets out = tmp/R mod p where tmp contains 64-bit words with
    /// the same 29,28,... bit positions as a field element.
    ///
    /// The values in field elements are in Montgomery form: x*R mod p where R =
    /// 2**257. Since we just multiplied two Montgomery values together, the result
    /// is x*y*R*R mod p. We wish to divide by R in order for the result also to be
    /// in Montgomery form.
    ///
    /// On entry: tmp[i] < 2**64
    /// On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29
    fn p256_reduce_degree(out: &mut P256FEle, tmp: &[u64; 17]) {
        // The following table may be helpful when reading this code:
        //
        // Limb number:   0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10...
        // Width (bits):  29| 28| 29| 28| 29| 28| 29| 28| 29| 28| 29
        // Start bit:     0 | 29| 57| 86|114|143|171|200|228|257|285
        //   (odd phase): 0 | 28| 57| 85|114|142|171|199|228|256|285
        let mut tmp2 = [0u32; 18];
        let (mut carry, mut x, mut x_mask);

        // tmp contains 64-bit words with the same 29,28,29-bit positions as an
        // field element. So the top of an element of tmp might overlap with
        // another element two positions down. The following loop eliminates
        // this overlap.
        tmp2[0] = Self::uint32(tmp[0]) & BOTTOM_29BITS;

        tmp2[1] = Self::uint32(tmp[0]) >> 29;
        tmp2[1] |= (Self::uint32(tmp[0]>>32) << 3) & BOTTOM_28BITS;
        tmp2[1] = tmp2[1].wrapping_add(Self::uint32(tmp[1]) & BOTTOM_28BITS);
        carry = tmp2[1] >> 28;
        tmp2[1] &= BOTTOM_28BITS;

        let mut i = 2;
        while i < 17 {
            tmp2[i] = (Self::uint32(tmp[i-2] >> 32)) >> 25;
            tmp2[i] = tmp2[i].wrapping_add((Self::uint32(tmp[i-1])) >> 28);
            tmp2[i] = tmp2[i].wrapping_add((Self::uint32(tmp[i-1]>>32) << 4) & BOTTOM_29BITS);
            tmp2[i] = tmp2[i].wrapping_add(Self::uint32(tmp[i]) & BOTTOM_29BITS);
            tmp2[i] = tmp2[i].wrapping_add(carry);
            carry = tmp2[i] >> 29;
            tmp2[i] &= BOTTOM_29BITS;

            i += 1;
            if i == 17 {
                break;
            }
            tmp2[i] = Self::uint32(tmp[i-2]>>32) >> 25;
            tmp2[i] = tmp2[i].wrapping_add(Self::uint32(tmp[i-1]) >> 29);
            tmp2[i] = tmp2[i].wrapping_add(((Self::uint32(tmp[i-1] >> 32)) << 3) & BOTTOM_28BITS);
            tmp2[i] = tmp2[i].wrapping_add(Self::uint32(tmp[i]) & BOTTOM_28BITS);
            tmp2[i] = tmp2[i].wrapping_add(carry);
            carry = tmp2[i] >> 28;
            tmp2[i] &= BOTTOM_28BITS;
            i += 1;
        }

        tmp2[17] = Self::uint32(tmp[15]>>32) >> 25;
        tmp2[17] = tmp2[17].wrapping_add(Self::uint32(tmp[16]) >> 29);
        tmp2[17] = tmp2[17].wrapping_add(Self::uint32(tmp[16]>>32) << 3);
        tmp2[17] = tmp2[17].wrapping_add(carry);

        // Montgomery elimination of terms:
        //
        // Since R is 2**257, we can divide by R with a bitwise shift if we can
        // ensure that the right-most 257 bits are all zero. We can make that true
        // by adding multiplies of p without affecting the value.
        //
        // So we eliminate limbs from right to left. Since the bottom 29 bits of p
        // are all ones, then by adding tmp2[0]*p to tmp2 we'll make tmp2[0] == 0.
        // We can do that for 8 further limbs and then right shift to eliminate the
        // extra factor of R.
        for i in (0..P256_LIMBS).step_by(2) {
            tmp2[i+1] = tmp2[i+1].wrapping_add(tmp2[i] >> 29);
            x = tmp2[i] & BOTTOM_29BITS;
            x_mask = Self::non_zero_to_all_ones(x);
            tmp2[i] = 0;

            // The bounds calculations for this loop are tricky. Each iteration of
            // the loop eliminates two words by adding values to words to their
            // right.
            //
            // The following table contains the amounts added to each word (as an
            // offset from the value of i at the top of the loop). The amounts are
            // accounted for from the first and second half of the loop separately
            // and are written as, for example, 28 to mean a value <2**28.
            //
            // Word:                   3   4   5   6   7   8   9   10
            // Added in top half:     28  11      29  21  29  28
            //                                        28  29
            //                                            29
            // Added in bottom half:      29  10      28  21  28   28
            //                                            29
            //
            // The value that is currently offset 7 will be offset 5 for the next
            // iteration and then offset 3 for the iteration after that. Therefore
            // the total value added will be the values added at 7, 5 and 3.
            //
            // The following table accumulates these values. The sums at the bottom
            // are written as, for example, 29+28, to mean a value < 2**29+2**28.
            //
            // Word:                   3   4   5   6   7   8   9  10  11  12  13
            //                        28  11  10  29  21  29  28  28  28  28  28
            //                            29  28  11  28  29  28  29  28  29  28
            //                                    29  28  21  21  29  21  29  21
            //                                        10  29  28  21  28  21  28
            //                                        28  29  28  29  28  29  28
            //                                            11  10  29  10  29  10
            //                                            29  28  11  28  11
            //                                                    29      29
            //                        --------------------------------------------
            //                                                30+ 31+ 30+ 31+ 30+
            //                                                28+ 29+ 28+ 29+ 21+
            //                                                21+ 28+ 21+ 28+ 10
            //                                                10  21+ 10  21+
            //                                                    11      11
            //
            // So the greatest amount is added to tmp2[10] and tmp2[12]. If
            // tmp2[10/12] has an initial value of <2**29, then the maximum value
            // will be < 2**31 + 2**30 + 2**28 + 2**21 + 2**11, which is < 2**32,
            // as required.
            tmp2[i+3] = tmp2[i+3].wrapping_add((x << 10) & BOTTOM_28BITS);
            tmp2[i+4] = tmp2[i+4].wrapping_add(x >> 18);

            tmp2[i+6] = tmp2[i+6].wrapping_add((x << 21) & BOTTOM_29BITS);
            tmp2[i+7] = tmp2[i+7].wrapping_add(x >> 8);

            // At position 200, which is the starting bit position for word 7, we
            // have a factor of 0xf000000 = 2**28 - 2**24.
            tmp2[i+7] = tmp2[i+7].wrapping_add(0x10000000 & x_mask);
            tmp2[i+8] = tmp2[i+8].wrapping_add((x - 1) & x_mask);
            tmp2[i+7] = tmp2[i+7].wrapping_sub((x << 24) & BOTTOM_28BITS);
            tmp2[i+8] = tmp2[i+8].wrapping_sub(x >> 4);

            tmp2[i+8] = tmp2[i+8].wrapping_add(0x20000000 & x_mask);
            tmp2[i+8] = tmp2[i+8].wrapping_sub(x);
            tmp2[i+8] = tmp2[i+8].wrapping_add((x << 28) & BOTTOM_29BITS);
            tmp2[i+9] = tmp2[i+9].wrapping_add(((x >> 1) - 1) & x_mask);

            if (i + 1) == P256_LIMBS {
                break;
            }
            tmp2[i+2] = tmp2[i+2].wrapping_add(tmp2[i+1] >> 28);
            x = tmp2[i+1] & BOTTOM_28BITS;
            x_mask = Self::non_zero_to_all_ones(x);
            tmp2[i+1] = 0;

            tmp2[i+4] = tmp2[i+4].wrapping_add((x << 11) & BOTTOM_29BITS);
            tmp2[i+5] = tmp2[i+5].wrapping_add(x >> 18);

            tmp2[i+7] = tmp2[i+7].wrapping_add((x << 21) & BOTTOM_28BITS);
            tmp2[i+8] = tmp2[i+8].wrapping_add(x >> 7);

            // At position 199, which is the starting bit of the 8th word when
            // dealing with a context starting on an odd word, we have a factor of
            // 0x1e000000 = 2**29 - 2**25. Since we have not updated i, the 8th
            // word from i+1 is i+8.
            tmp2[i+8] = tmp2[i+8].wrapping_add(0x20000000 & x_mask);
            tmp2[i+9] = tmp2[i+9].wrapping_add((x - 1) & x_mask);
            tmp2[i+8] = tmp2[i+8].wrapping_sub((x << 25) & BOTTOM_29BITS);
            tmp2[i+9] = tmp2[i+9].wrapping_sub(x >> 4);

            tmp2[i+9] = tmp2[i+9].wrapping_add(0x10000000 & x_mask);
            tmp2[i+9] = tmp2[i+9].wrapping_sub(x);
            tmp2[i+10] = tmp2[i+10].wrapping_add((x - 1) & x_mask);
        }

        // We merge the right shift with a carry chain. The words above 2**257 have
        // widths of 28,29,... which we need to correct when copying them down.
        carry = 0;
        let mut i = 0;
        while i < 8 {
            // The maximum value of tmp2[i + 9] occurs on the first iteration and
            // is < 2**30+2**29+2**28. Adding 2**29 (from tmp2[i + 10]) is
            // therefore safe.
            out[i] = tmp2[i+9];
            out[i] = out[i].wrapping_add(carry);
            out[i] = out[i].wrapping_add((tmp2[i+10] << 28) & BOTTOM_29BITS);
            carry = out[i] >> 29;
            out[i] &= BOTTOM_29BITS;

            i += 1;
            out[i] = tmp2[i+9] >> 1;
            out[i] = out[i].wrapping_add(carry);
            carry = out[i] >> 28;
            out[i] &= BOTTOM_28BITS;
            i += 1;
        }

        out[8] = tmp2[17];
        out[8] = out[8].wrapping_add(carry);
        carry = out[8] >> 29;
        out[8] &= BOTTOM_29BITS;

        Self::p256_reduce_carry(out, carry)
    }
    
    #[inline]
    fn uint64(n: u32) -> u64 {
        n as u64
    }
    
    fn p256_square_a(out: *mut P256FEle, a: *const P256FEle) {
        let (out, a) = unsafe {
            (&mut *out, &*a)
        };
        Self::p256_square(out, a);
    }
    
    fn p256_square(out: &mut P256FEle, a: &P256FEle) {
        let mut tmp = [0u64; 17];
        tmp[0] = Self::uint64(a[0]).wrapping_mul(Self::uint64(a[0]));
        tmp[1] = Self::uint64(a[0]).wrapping_mul(Self::uint64(a[1]) << 1);
        tmp[2] = Self::uint64(a[0]).wrapping_mul(Self::uint64(a[2])<<1)
            .wrapping_add(Self::uint64(a[1]).wrapping_mul(Self::uint64(a[1])<<1));
        tmp[3] = Self::uint64(a[0]).wrapping_mul(Self::uint64(a[3])<<1).wrapping_add(
        Self::uint64(a[1]).wrapping_mul(Self::uint64(a[2])<<1));
        tmp[4] = Self::uint64(a[0]).wrapping_mul(Self::uint64(a[4])<<1).wrapping_add(
        Self::uint64(a[1]).wrapping_mul(Self::uint64(a[3])<<2)).wrapping_add(
        Self::uint64(a[2]).wrapping_mul(Self::uint64(a[2])));
        tmp[5] = Self::uint64(a[0]).wrapping_mul(Self::uint64(a[5])<<1).wrapping_add(
        Self::uint64(a[1]).wrapping_mul(Self::uint64(a[4])<<1)).wrapping_add(
        Self::uint64(a[2]).wrapping_mul(Self::uint64(a[3])<<1));
        tmp[6] = Self::uint64(a[0]).wrapping_mul(Self::uint64(a[6])<<1).wrapping_add(
        Self::uint64(a[1]).wrapping_mul(Self::uint64(a[5])<<2)).wrapping_add(
        Self::uint64(a[2]).wrapping_mul(Self::uint64(a[4])<<1)).wrapping_add(
        Self::uint64(a[3]).wrapping_mul(Self::uint64(a[3])<<1));
        tmp[7] = Self::uint64(a[0]).wrapping_mul(Self::uint64(a[7])<<1).wrapping_add(
        Self::uint64(a[1]).wrapping_mul(Self::uint64(a[6])<<1)).wrapping_add(
        Self::uint64(a[2]).wrapping_mul(Self::uint64(a[5])<<1)).wrapping_add(
        Self::uint64(a[3]).wrapping_mul(Self::uint64(a[4])<<1));
        // tmp[8] has the greatest value of 2**61 + 2**60 + 2**61 + 2**60 + 2**60,
        // which is < 2**64 as required.
        tmp[8] = Self::uint64(a[0]).wrapping_mul(Self::uint64(a[8])<<1).wrapping_add(
        Self::uint64(a[1]).wrapping_mul(Self::uint64(a[7])<<2)).wrapping_add(
        Self::uint64(a[2]).wrapping_mul(Self::uint64(a[6])<<1)).wrapping_add(
        Self::uint64(a[3]).wrapping_mul(Self::uint64(a[5])<<2)).wrapping_add(
        Self::uint64(a[4]).wrapping_mul(Self::uint64(a[4])));
        tmp[9] = Self::uint64(a[1]).wrapping_mul(Self::uint64(a[8])<<1).wrapping_add(
        Self::uint64(a[2]).wrapping_mul(Self::uint64(a[7])<<1)).wrapping_add(
        Self::uint64(a[3]).wrapping_mul(Self::uint64(a[6])<<1)).wrapping_add(
        Self::uint64(a[4]).wrapping_mul(Self::uint64(a[5])<<1));
        tmp[10] = Self::uint64(a[2]).wrapping_mul(Self::uint64(a[8])<<1).wrapping_add(
        Self::uint64(a[3]).wrapping_mul(Self::uint64(a[7])<<2)).wrapping_add(
        Self::uint64(a[4]).wrapping_mul(Self::uint64(a[6])<<1)).wrapping_add(
        Self::uint64(a[5]).wrapping_mul(Self::uint64(a[5])<<1));
        tmp[11] = Self::uint64(a[3]).wrapping_mul(Self::uint64(a[8])<<1).wrapping_add(
        Self::uint64(a[4]).wrapping_mul(Self::uint64(a[7])<<1)).wrapping_add(
        Self::uint64(a[5]).wrapping_mul(Self::uint64(a[6])<<1));
        tmp[12] = Self::uint64(a[4]).wrapping_mul(Self::uint64(a[8])<<1).wrapping_add(
        Self::uint64(a[5]).wrapping_mul(Self::uint64(a[7])<<2)).wrapping_add(
        Self::uint64(a[6]).wrapping_mul(Self::uint64(a[6])));
        tmp[13] = Self::uint64(a[5]).wrapping_mul(Self::uint64(a[8])<<1).wrapping_add(
        Self::uint64(a[6]).wrapping_mul(Self::uint64(a[7])<<1));
        tmp[14] = Self::uint64(a[6]).wrapping_mul(Self::uint64(a[8])<<1).wrapping_add(
        Self::uint64(a[7]).wrapping_mul(Self::uint64(a[7])<<1));
        tmp[15] = Self::uint64(a[7]).wrapping_mul(Self::uint64(a[8]) << 1);
        tmp[16] = Self::uint64(a[8]).wrapping_mul(Self::uint64(a[8]));

        Self::p256_reduce_degree(out, &tmp);
    }
    
    fn p256_mul_a(out: *mut P256FEle, a: *const P256FEle, b: *const P256FEle) {
        let (out, a, b) = unsafe {
            (&mut *out, &*a, &*b)
        };
        
        Self::p256_mul(out, a, b);
    }
    
    fn p256_mul(out: &mut P256FEle, a: &P256FEle, b: &P256FEle) {
        let mut tmp = [0u64; 17];
        tmp[0] = Self::uint64(a[0]).wrapping_mul(Self::uint64(b[0]));
        tmp[1] = Self::uint64(a[0]).wrapping_mul(Self::uint64(b[1])<<0).wrapping_add(
            Self::uint64(a[1]).wrapping_mul(Self::uint64(b[0])<<0));
        tmp[2] = Self::uint64(a[0]).wrapping_mul(Self::uint64(b[2])<<0).wrapping_add(
            Self::uint64(a[1]).wrapping_mul(Self::uint64(b[1])<<1)).wrapping_add(
            Self::uint64(a[2]).wrapping_mul(Self::uint64(b[0])<<0));
        tmp[3] = Self::uint64(a[0]).wrapping_mul(Self::uint64(b[3])<<0).wrapping_add(
            Self::uint64(a[1]).wrapping_mul(Self::uint64(b[2])<<0)).wrapping_add(
            Self::uint64(a[2]).wrapping_mul(Self::uint64(b[1])<<0)).wrapping_add(
            Self::uint64(a[3]).wrapping_mul(Self::uint64(b[0])<<0));
        tmp[4] = Self::uint64(a[0]).wrapping_mul(Self::uint64(b[4])<<0).wrapping_add(
            Self::uint64(a[1]).wrapping_mul(Self::uint64(b[3])<<1)).wrapping_add(
            Self::uint64(a[2]).wrapping_mul(Self::uint64(b[2])<<0)).wrapping_add(
            Self::uint64(a[3]).wrapping_mul(Self::uint64(b[1])<<1)).wrapping_add(
            Self::uint64(a[4]).wrapping_mul(Self::uint64(b[0])<<0));
        tmp[5] = Self::uint64(a[0]).wrapping_mul(Self::uint64(b[5])<<0).wrapping_add(
            Self::uint64(a[1]).wrapping_mul(Self::uint64(b[4])<<0)).wrapping_add(
            Self::uint64(a[2]).wrapping_mul(Self::uint64(b[3])<<0)).wrapping_add(
            Self::uint64(a[3]).wrapping_mul(Self::uint64(b[2])<<0)).wrapping_add(
            Self::uint64(a[4]).wrapping_mul(Self::uint64(b[1])<<0)).wrapping_add(
            Self::uint64(a[5]).wrapping_mul(Self::uint64(b[0])<<0));
        tmp[6] = Self::uint64(a[0]).wrapping_mul(Self::uint64(b[6])<<0).wrapping_add(
            Self::uint64(a[1]).wrapping_mul(Self::uint64(b[5])<<1)).wrapping_add(
            Self::uint64(a[2]).wrapping_mul(Self::uint64(b[4])<<0)).wrapping_add(
            Self::uint64(a[3]).wrapping_mul(Self::uint64(b[3])<<1)).wrapping_add(
            Self::uint64(a[4]).wrapping_mul(Self::uint64(b[2])<<0)).wrapping_add(
            Self::uint64(a[5]).wrapping_mul(Self::uint64(b[1])<<1)).wrapping_add(
            Self::uint64(a[6]).wrapping_mul(Self::uint64(b[0])<<0));
        tmp[7] = Self::uint64(a[0]).wrapping_mul(Self::uint64(b[7])<<0).wrapping_add(
            Self::uint64(a[1]).wrapping_mul(Self::uint64(b[6])<<0)).wrapping_add(
            Self::uint64(a[2]).wrapping_mul(Self::uint64(b[5])<<0)).wrapping_add(
            Self::uint64(a[3]).wrapping_mul(Self::uint64(b[4])<<0)).wrapping_add(
            Self::uint64(a[4]).wrapping_mul(Self::uint64(b[3])<<0)).wrapping_add(
            Self::uint64(a[5]).wrapping_mul(Self::uint64(b[2])<<0)).wrapping_add(
            Self::uint64(a[6]).wrapping_mul(Self::uint64(b[1])<<0)).wrapping_add(
            Self::uint64(a[7]).wrapping_mul(Self::uint64(b[0])<<0));
        // tmp[8] has the greatest value but doesn't overflow. See logica 
        // p256Square.
        tmp[8] = Self::uint64(a[0]).wrapping_mul(Self::uint64(b[8])<<0).wrapping_add(
            Self::uint64(a[1]).wrapping_mul(Self::uint64(b[7])<<1)).wrapping_add(
            Self::uint64(a[2]).wrapping_mul(Self::uint64(b[6])<<0)).wrapping_add(
            Self::uint64(a[3]).wrapping_mul(Self::uint64(b[5])<<1)).wrapping_add(
            Self::uint64(a[4]).wrapping_mul(Self::uint64(b[4])<<0)).wrapping_add(
            Self::uint64(a[5]).wrapping_mul(Self::uint64(b[3])<<1)).wrapping_add(
            Self::uint64(a[6]).wrapping_mul(Self::uint64(b[2])<<0)).wrapping_add(
            Self::uint64(a[7]).wrapping_mul(Self::uint64(b[1])<<1)).wrapping_add(
            Self::uint64(a[8]).wrapping_mul(Self::uint64(b[0])<<0));
        tmp[9] = Self::uint64(a[1]).wrapping_mul(Self::uint64(b[8])<<0).wrapping_add(
            Self::uint64(a[2]).wrapping_mul(Self::uint64(b[7])<<0)).wrapping_add(
            Self::uint64(a[3]).wrapping_mul(Self::uint64(b[6])<<0)).wrapping_add(
            Self::uint64(a[4]).wrapping_mul(Self::uint64(b[5])<<0)).wrapping_add(
            Self::uint64(a[5]).wrapping_mul(Self::uint64(b[4])<<0)).wrapping_add(
            Self::uint64(a[6]).wrapping_mul(Self::uint64(b[3])<<0)).wrapping_add(
            Self::uint64(a[7]).wrapping_mul(Self::uint64(b[2])<<0)).wrapping_add(
            Self::uint64(a[8]).wrapping_mul(Self::uint64(b[1])<<0));
        tmp[10] = Self::uint64(a[2]).wrapping_mul(Self::uint64(b[8])<<0).wrapping_add(
            Self::uint64(a[3]).wrapping_mul(Self::uint64(b[7])<<1)).wrapping_add(
            Self::uint64(a[4]).wrapping_mul(Self::uint64(b[6])<<0)).wrapping_add(
            Self::uint64(a[5]).wrapping_mul(Self::uint64(b[5])<<1)).wrapping_add(
            Self::uint64(a[6]).wrapping_mul(Self::uint64(b[4])<<0)).wrapping_add(
            Self::uint64(a[7]).wrapping_mul(Self::uint64(b[3])<<1)).wrapping_add(
            Self::uint64(a[8]).wrapping_mul(Self::uint64(b[2])<<0));
        tmp[11] = Self::uint64(a[3]).wrapping_mul(Self::uint64(b[8])<<0).wrapping_add(
            Self::uint64(a[4]).wrapping_mul(Self::uint64(b[7])<<0)).wrapping_add(
            Self::uint64(a[5]).wrapping_mul(Self::uint64(b[6])<<0)).wrapping_add(
            Self::uint64(a[6]).wrapping_mul(Self::uint64(b[5])<<0)).wrapping_add(
            Self::uint64(a[7]).wrapping_mul(Self::uint64(b[4])<<0)).wrapping_add(
            Self::uint64(a[8]).wrapping_mul(Self::uint64(b[3])<<0));
        tmp[12] = Self::uint64(a[4]).wrapping_mul(Self::uint64(b[8])<<0).wrapping_add(
            Self::uint64(a[5]).wrapping_mul(Self::uint64(b[7])<<1)).wrapping_add(
            Self::uint64(a[6]).wrapping_mul(Self::uint64(b[6])<<0)).wrapping_add(
            Self::uint64(a[7]).wrapping_mul(Self::uint64(b[5])<<1)).wrapping_add(
            Self::uint64(a[8]).wrapping_mul(Self::uint64(b[4])<<0));
        tmp[13] = Self::uint64(a[5]).wrapping_mul(Self::uint64(b[8])<<0).wrapping_add(
            Self::uint64(a[6]).wrapping_mul(Self::uint64(b[7])<<0)).wrapping_add(
            Self::uint64(a[7]).wrapping_mul(Self::uint64(b[6])<<0)).wrapping_add(
            Self::uint64(a[8]).wrapping_mul(Self::uint64(b[5])<<0));
        tmp[14] = Self::uint64(a[6]).wrapping_mul(Self::uint64(b[8])<<0).wrapping_add(
            Self::uint64(a[7]).wrapping_mul(Self::uint64(b[7])<<1)).wrapping_add(
            Self::uint64(a[8]).wrapping_mul(Self::uint64(b[6])<<0));
        tmp[15] = Self::uint64(a[7]).wrapping_mul(Self::uint64(b[8])<<0).wrapping_add(
            Self::uint64(a[8]).wrapping_mul(Self::uint64(b[7])<<0));
        tmp[16] = Self::uint64(a[8]).wrapping_mul(Self::uint64(b[8]) << 0);

        Self::p256_reduce_degree(out, &tmp);
    }
    
    fn p256_assign(out: &mut P256FEle, a: &P256FEle) {
        *out = *a;
    }

    /// p256Invert calculates |out| = |in|^{-1}
    ///
    /// Based on Fermat's Little Theorem:
    ///   a^p = a (mod p)
    ///   a^{p-1} = 1 (mod p)
    ///   a^{p-2} = a^{-1} (mod p)
    fn p256_invert(out: &mut P256FEle, a: &P256FEle) {
        let (mut ftmp, mut ftmp2) = ([0u32; P256_LIMBS], [0u32; P256_LIMBS]);
        let (mut e2, mut e4, mut e8, mut e16, mut e32, mut e64) = (
            [0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],
            );
        Self::p256_square(&mut ftmp, a);// 2^1
        Self::p256_mul_a(&mut ftmp, a, &ftmp); // 2^2 - 2^0
        Self::p256_assign(&mut e2, &ftmp);
        Self::p256_square_a(&mut ftmp, &ftmp);   // 2^3 - 2^1
        Self::p256_square_a(&mut ftmp, &ftmp);   // 2^4 - 2^2
        Self::p256_mul_a(&mut ftmp, &ftmp, &e2); // 2^4 - 2^0
        Self::p256_assign(&mut e4, &ftmp);
        Self::p256_square_a(&mut ftmp, &ftmp);   // 2^5 - 2^1
        Self::p256_square_a(&mut ftmp, &ftmp);   // 2^6 - 2^2
        Self::p256_square_a(&mut ftmp, &ftmp);   // 2^7 - 2^3
        Self::p256_square_a(&mut ftmp, &ftmp);   // 2^8 - 2^4
        Self::p256_mul_a(&mut ftmp, &ftmp, &e4); // 2^8 - 2^0
        Self::p256_assign(&mut e8, &ftmp);
        (0..8).for_each(|_| {Self::p256_square_a(&mut ftmp, &ftmp);}); // 2^16 - 2^8
        Self::p256_mul_a(&mut ftmp, &ftmp, &e8); // 2^16 - 2^0
        Self::p256_assign(&mut e16, &ftmp);
        (0..16).for_each(|_| {Self::p256_square_a(&mut ftmp, &ftmp);}); // 2^32 - 2^16
        Self::p256_mul_a(&mut ftmp, &ftmp, &e16); // 2^32 - 2^0
        Self::p256_assign(&mut e32, &ftmp);
        (0..32).for_each(|_|{
            Self::p256_square_a(&mut ftmp, &ftmp);
        }); // 2^64 - 2^32
        Self::p256_assign(&mut e64, &ftmp);
        Self::p256_mul_a(&mut ftmp, &ftmp, a); // 2^64 - 2^32 + 2^0
        (0..192).for_each(|_|{
            Self::p256_square_a(&mut ftmp, &ftmp);
        }); // 2^256 - 2^224 + 2^192

        Self::p256_mul(&mut ftmp2, &e64, &e32); // 2^64 - 2^0
        (0..16).for_each(|_|{
            Self::p256_square_a(&mut ftmp2, &ftmp2);
        }); // 2^80 - 2^16
        Self::p256_mul_a(&mut ftmp2, &ftmp2, &e16); // 2^80 - 2^0
        (0..8).for_each(|_| {
            Self::p256_square_a(&mut ftmp2, &ftmp2);
        }); // 2^88 - 2^8
        Self::p256_mul_a(&mut ftmp2, &ftmp2, &e8); // 2^88 - 2^0
        (0..4).for_each(|_|{
            Self::p256_square_a(&mut ftmp2, &ftmp2);
        }); // 2^92 - 2^4
        Self::p256_mul_a(&mut ftmp2, &ftmp2, &e4); // 2^92 - 2^0
        Self::p256_square_a(&mut ftmp2, &ftmp2);   // 2^93 - 2^1
        Self::p256_square_a(&mut ftmp2, &ftmp2);   // 2^94 - 2^2
        Self::p256_mul_a(&mut ftmp2, &ftmp2, &e2); // 2^94 - 2^0
        Self::p256_square_a(&mut ftmp2, &ftmp2);   // 2^95 - 2^1
        Self::p256_square_a(&mut ftmp2, &ftmp2);   // 2^96 - 2^2
        Self::p256_mul_a(&mut ftmp2, &ftmp2, a);  // 2^96 - 3

        Self::p256_mul(out, &ftmp2, &ftmp); // 2^256 - 2^224 + 2^192 + 2^96 - 3
    }

    /// p256Scalar3 sets out=3*out.
    ///
    /// On entry: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
    /// On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
    fn p256_scalar3(out: &mut P256FEle) {
        let (mut carry, mut i) = (0u32, 0);
        while i < out.len() {
            out[i] = out[i].wrapping_mul(3);
            out[i] = out[i].wrapping_add(carry);
            carry = out[i] >> 29;
            out[i] &= BOTTOM_29BITS;

            i+=1;
            if i == P256_LIMBS {
                break;
            }
            
            out[i] = out[i].wrapping_mul(3);
            out[i] = out[i].wrapping_add(carry);
            carry = out[i] >> 28;
            out[i] &= BOTTOM_28BITS;
            i += 1;
        }
        
        Self::p256_reduce_carry(out, carry);
    }

    /// p256Scalar4 sets out=4*out.
    ///
    /// On entry: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
    /// On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
    fn p256_scalar4(out: &mut P256FEle) {
        let (mut carry, mut i) = (0u32, 0usize);
        let mut next_carry;
        
        while i < out.len() {
            next_carry = out[i] >> 27;
            out[i] <<= 2;
            out[i] &= BOTTOM_29BITS; 
            out[i] = out[i].wrapping_add(carry);
            carry = next_carry.wrapping_add(out[i] >> 29);
            out[i] &= BOTTOM_29BITS;

            i += 1;
            if i == P256_LIMBS {
                break;
            }
            next_carry = out[i] >> 26;
            out[i] <<= 2;
            out[i] &= BOTTOM_28BITS;
            out[i] = out[i].wrapping_add(carry);
            carry = next_carry.wrapping_add(out[i] >> 28);
            out[i] &= BOTTOM_28BITS;
            i += 1;
        }
        
        Self::p256_reduce_carry(out, carry);
    }

    /// p256Scalar8 sets out=8*out.
    ///
    /// On entry: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
    /// On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
    fn p256_scalar8(out: &mut P256FEle) {
        let mut next_carry;
        let (mut carry, mut i) = (0, 0);
        while i < out.len() {
            next_carry = out[i] >> 26;
            out[i] <<= 3;
            out[i] &= BOTTOM_29BITS;
            out[i] = out[i].wrapping_add(carry);
            carry = next_carry.wrapping_add(out[i] >> 29);
            out[i] &= BOTTOM_29BITS;

            i += 1;
            if i == P256_LIMBS {
                break;
            }
            next_carry = out[i] >> 25;
            out[i] <<= 3;
            out[i] &= BOTTOM_28BITS;
            out[i] = out[i].wrapping_add(carry);
            carry = next_carry.wrapping_add(out[i] >> 28);
            out[i] &= BOTTOM_28BITS;
            i += 1;
        }
        
        Self::p256_reduce_carry(out, carry);
    }
    
    fn p256_point_double_a(xout: *mut P256FEle, yout: *mut P256FEle, zout: *mut P256FEle, x: *const P256FEle, y: *const P256FEle, z: *const P256FEle) {
        let (xout, yout, zout, x, y, z) = unsafe {
            (&mut *xout, &mut *yout, &mut *zout, &*x, &*y, &*z)
        };
        Self::p256_point_double(xout, yout, zout, x, y, z);
    }

    /// Group operations:
    ///
    /// Elements of the elliptic curve group are represented in Jacobian
    /// coordinates: (x, y, z). An affine point (x', y') is x'=x/z**2, y'=y/z**3 in
    /// Jacobian form.
    /// p256PointDouble sets {xOut,yOut,zOut} = 2*{x,y,z}.
    ///
    /// See https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
    fn p256_point_double(xout: &mut P256FEle, yout: &mut P256FEle, zout: &mut P256FEle, x: &P256FEle, y: &P256FEle, z: &P256FEle) {
        let (mut delta, mut gamma, mut alpha, mut beta, mut tmp, mut tmp2) = (
            [0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],
            );

        Self::p256_square(&mut delta, z);
        Self::p256_square(&mut gamma, y);
        Self::p256_mul(&mut beta, x, &gamma);

        Self::p256_sum(&mut tmp, x, &delta);
        Self::p256_diff(&mut tmp2, x, &delta);
        Self::p256_mul(&mut alpha, &tmp, &tmp2);
        Self::p256_scalar3(&mut alpha);

        Self::p256_sum(&mut tmp, y, z);
        Self::p256_square_a(&mut tmp, &tmp);
        Self::p256_diff_a(&mut tmp, &tmp, &gamma);
        Self::p256_diff(zout, &tmp, &delta);

        Self::p256_scalar4(&mut beta);
        Self::p256_square(xout, &alpha);
        Self::p256_diff_a(xout, xout, &beta);
        Self::p256_diff_a(xout, &*xout, &beta);

        Self::p256_diff(&mut tmp, &beta, xout);
        Self::p256_mul_a(&mut tmp, &alpha, &tmp);
        Self::p256_square(&mut tmp2, &gamma);
        Self::p256_scalar8(&mut tmp2);
        Self::p256_diff(yout, &tmp, &tmp2);
    }

    fn p256_point_add_mixed_a(xout: *mut P256FEle, yout: *mut P256FEle, zout: *mut P256FEle, x1: *const P256FEle, y1: *const P256FEle, z1: *const P256FEle, x2: *const P256FEle, y2: *const P256FEle) {
        let (xout, yout, zout, x1, y1, z1, x2, y2) = unsafe {
            (&mut *xout, &mut *yout, &mut *zout, &*x1, &*y1, &*z1, &*x2, &*y2)
        };
        
        Self::p256_point_add_mixed(xout, yout, zout, x1, y1, z1, x2, y2);
    }

    /// p256PointAddMixed sets {xOut,yOut,zOut} = {x1,y1,z1} + {x2,y2,1}.
    /// (i.e. the second point is affine.)
    ///
    /// See https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
    ///
    /// Note that this function does not handle P+P, infinity+P nor P+infinity
    /// correctly.
    fn p256_point_add_mixed(xout: &mut P256FEle, yout: &mut P256FEle, zout: &mut P256FEle, x1: &P256FEle, y1: &P256FEle, z1: &P256FEle, x2: &P256FEle, y2: &P256FEle) {
        let (mut z1z1, mut z1z1z1, mut s2, mut u2, mut h, mut i, mut j, mut r, mut rr, mut v, mut tmp) = (
            [0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],
            );

        Self::p256_square(&mut z1z1, z1);
        Self::p256_sum(&mut tmp, z1, z1);

        Self::p256_mul(&mut u2, x2, &z1z1);
        Self::p256_mul(&mut z1z1z1, z1, &z1z1);
        Self::p256_mul(&mut s2, y2, &z1z1z1);
        Self::p256_diff(&mut h, &u2, x1);
        Self::p256_sum(&mut i, &h, &h);
        Self::p256_square_a(&mut i, &i);
        Self::p256_mul(&mut j, &h, &i);
        Self::p256_diff(&mut r, &s2, y1);
        Self::p256_sum_a(&mut r, &r, &r);
        Self::p256_mul(&mut v, x1, &i);

        Self::p256_mul(zout, &tmp, &h);
        Self::p256_square(&mut rr, &r);
        Self::p256_diff(xout, &rr, &j);
        Self::p256_diff_a(xout, xout, &v);
        Self::p256_diff_a(xout, xout, &v);

        Self::p256_diff(&mut tmp, &v, xout);
        Self::p256_mul(yout, &tmp, &r);
        Self::p256_mul(&mut tmp, y1, &j);
        Self::p256_diff_a(yout, yout, &tmp);
        Self::p256_diff_a(yout, yout, &tmp);
    }

    /// p256PointAdd sets {xOut,yOut,zOut} = {x1,y1,z1} + {x2,y2,z2}.
    ///
    /// See https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
    ///
    /// Note that this function does not handle P+P, infinity+P nor P+infinity
    /// correctly.
    fn p256_point_add(xout: &mut P256FEle, yout: &mut P256FEle, zout: &mut P256FEle, x1: &P256FEle, y1: &P256FEle, z1: &P256FEle, x2: &P256FEle, y2: &P256FEle, z2: &P256FEle) {
        let (mut z1z1, mut z1z1z1, mut s2, mut u2, mut h, mut i, mut j, mut r, mut rr, mut v, mut tmp) = (
            [0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],
        );
        let (mut s1, mut z2z2, mut z2z2z2, mut u1) = ([0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],);
        
        Self::p256_square(&mut z1z1, z1);
        Self::p256_square(&mut z2z2, z2);
        Self::p256_mul(&mut u1, x1, &z2z2);

        Self::p256_sum(&mut tmp, z1, z2);
        Self::p256_square_a(&mut tmp, &tmp);
        Self::p256_diff_a(&mut tmp, &tmp, &z1z1);
        Self::p256_diff_a(&mut tmp, &tmp, &z2z2);

        Self::p256_mul(&mut z2z2z2, z2, &z2z2);
        Self::p256_mul(&mut s1, y1, &z2z2z2);

        Self::p256_mul(&mut u2, x2, &z1z1);
        Self::p256_mul(&mut z1z1z1, z1, &z1z1);
        Self::p256_mul(&mut s2, y2, &z1z1z1);
        Self::p256_diff(&mut h, &u2, &u1);
        Self::p256_sum(&mut i, &h, &h);
        Self::p256_square_a(&mut i, &i);
        Self::p256_mul(&mut j, &h, &i);
        Self::p256_diff(&mut r, &s2, &s1);
        Self::p256_sum_a(&mut r, &r, &r);
        Self::p256_mul(&mut v, &u1, &i);

        Self::p256_mul(zout, &tmp, &h);
        Self::p256_square(&mut rr, &r);
        Self::p256_diff(xout, &rr, &j);
        Self::p256_diff_a(xout, xout, &v);
        Self::p256_diff_a(xout, xout, &v);

        Self::p256_diff(&mut tmp, &v, xout);
        Self::p256_mul(yout, &tmp, &r);
        Self::p256_mul(&mut tmp, &s1, &j);
        Self::p256_diff_a(yout, yout, &tmp);
        Self::p256_diff_a(yout, yout, &tmp);
    }

    /// p256CopyConditional sets out=in if mask = 0xffffffff in constant time.
    ///
    /// On entry: mask is either 0 or 0xffffffff.
    fn p256_copy_conditional(out: &mut P256FEle, a: &P256FEle, mask: u32) {
        out.iter_mut().zip(a.iter()).for_each(|(x, &y)| {
            *x ^= mask & (y ^ (*x));
        });
    }

    /// p256SelectAffinePoint sets {out_x,out_y} to the index'th entry of table.
    /// On entry: index < 16, table[0] must be zero.
    fn p256_select_affine_point(xout: &mut P256FEle, yout: &mut P256FEle, mut table: &[u32], index: u32) {
        xout.iter_mut().zip(yout.iter_mut()).for_each(|(x, y)| {
            *x = 0; *y = 0;
        });
        for i in 1..16u32 {
            let mut mask = i ^ index;
            mask |= mask >> 2;
            mask |= mask >> 1;
            mask &= 1;
            mask = mask.wrapping_sub(1);
            xout.iter_mut().zip(table.iter()).for_each(|(x, &t)| {
                *x |= t & mask;
            });
            table = &table[xout.len()..];
            yout.iter_mut().zip(table.iter()).for_each(|(y, &t)|{
                *y |= t & mask;
            });
            table = &table[xout.len()..];
        }
    }

    /// p256SelectJacobianPoint sets {out_x,out_y,out_z} to the index'th entry of
    /// table.
    /// On entry: index < 16, table[0] must be zero.
    fn p256_select_jacobian_point(xout: &mut P256FEle, yout: &mut P256FEle, zout: &mut P256FEle, table: &[[[u32; P256_LIMBS]; 3]; 16], index: u32) {
        xout.iter_mut().zip(yout.iter_mut().zip(zout.iter_mut())).for_each(|(x, (y, z))| {
            *x = 0; *y = 0; *z = 0;
        });


        // The implicit value at index 0 is all zero. We don't need to perform that
        // iteration of the loop because we already set out_* to zero.
        for i in 1..16u32 {
            let mut mask = i ^ index;
            mask |= mask >> 2;
            mask |= mask >> 1;
            mask = if (mask & 1) == 1 {0} else {u32::MAX};
            for (j, x) in xout.iter_mut().enumerate() {
                *x |= table[i as usize][0][j] & mask;
            }
            for (j, y) in yout.iter_mut().enumerate() {
                *y |= table[i as usize][1][j] & mask;
            }
            for (j, z) in zout.iter_mut().enumerate() {
                *z |= table[i as usize][2][j] & mask;
            }
        }
    }
    
    fn p256_get_bit(scalar: &[u8; 32], bit: u32) -> u32 {
        let bit = bit as usize;
        ((scalar[bit >> 3] as u32) >> (bit & 7)) & 1
    }

    /// p256ScalarBaseMult sets {xOut,yOut,zOut} = scalar*G where scalar is a
    /// little-endian number. Note that the value of scalar must be less than the
    /// order of the group.
    fn p256_scalar_base_mult(xout: &mut P256FEle, yout: &mut P256FEle, zout: &mut P256FEle, scalar: &[u8; 32]) {
        let mut nisinfinitymask = !0u32;
        let (mut pisnoninfinitemask, mut mask, mut tableoffset);
        let (mut px, mut py, mut tx, mut ty, mut tz) = (
            [0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],
            );
        xout.iter_mut().zip(yout.iter_mut().zip(zout.iter_mut())).for_each(|(x,(y,z))| {
            *x = 0; *y = 0; *z = 0;
        });

        // The loop adds bits at positions 0, 64, 128 and 192, followed by
        // positions 32,96,160 and 224 and does this 32 times.
        for i in 0..32u32 {
            if i != 0 {
                Self::p256_point_double_a(xout, yout, zout, xout, yout, zout);
            }
            tableoffset = 0;
            for j in (0..=32u32).step_by(32) {
                let bit0 = Self::p256_get_bit(scalar, 31-i+j);
                let bit1 = Self::p256_get_bit(scalar, 95-i+j);
                let bit2 = Self::p256_get_bit(scalar, 159-i+j);
                let bit3 = Self::p256_get_bit(scalar, 223-i+j);
                let index = bit0 | (bit1 << 1) | (bit2 << 2) | (bit3 << 3);

                Self::p256_select_affine_point(&mut px, &mut py, &P256_PRECOMPUTED[(tableoffset as usize)..], index);
                tableoffset += 30 * (P256_LIMBS as u32);

                // Since scalar is less than the order of the group, we know that
                // {xOut,yOut,zOut} != {px,py,1}, unless both are zero, which we handle
                // below.
                Self::p256_point_add_mixed(&mut tx, &mut ty, &mut tz, xout, yout, zout, &px, &py);
                // The result of pointAddMixed is incorrect if {xOut,yOut,zOut} is zero
                // (a.k.a.  the point at infinity). We handle that situation by
                // copying the point from the table.
                Self::p256_copy_conditional(xout, &px, nisinfinitymask);
                Self::p256_copy_conditional(yout, &py, nisinfinitymask);
                Self::p256_copy_conditional(zout, &P256_ONE, nisinfinitymask);

                // Equally, the result is also wrong if the point from the table is
                // zero, which happens when the index is zero. We handle that by
                // only copying from {tx,ty,tz} to {xOut,yOut,zOut} if index != 0.
                pisnoninfinitemask = Self::non_zero_to_all_ones(index);
                mask = pisnoninfinitemask & (!nisinfinitymask);
                Self::p256_copy_conditional(xout, &tx, mask);
                Self::p256_copy_conditional(yout, &ty, mask);
                Self::p256_copy_conditional(zout, &tz, mask);
                // If p was not zero, then n is now non-zero.
                nisinfinitymask &= !pisnoninfinitemask;
            }
        }
    }

    /// p256PointToAffine converts a Jacobian point to an affine point. If the input
    /// is the point at infinity then it returns (0, 0) in constant time.
    fn p256_point_to_affine(xout: &mut P256FEle, yout: &mut P256FEle, x: &P256FEle, y: &P256FEle, z: &P256FEle) {
        let (mut zinv, mut zinvsq) = ([0u32; P256_LIMBS], [0u32; P256_LIMBS]);
        Self::p256_invert(&mut zinv, z);
        Self::p256_square(&mut zinvsq, &zinv);
        Self::p256_mul(xout, x, &zinvsq);
        Self::p256_mul_a(&mut zinv, &zinv, &zinvsq);
        Self::p256_mul(yout, y, &zinv);
    }
    
    fn p256_to_bigint(&self, a: &P256FEle) -> BigInt {
        let mut result = Nat::from(a[P256_LIMBS - 1]);
        for (i, &ele) in a.iter().enumerate().rev().skip(1) {
            if (i & 1) == 0 {
                result <<= 29;
            } else {
                result <<= 28;
            }
            
            result += ele;
        }
        
        let mut result = BigInt::from(result);
        result *= self.r_inv.clone();
        result.rem_euclid_assign(self.cp.field_order().clone());
        result
    }
    
    fn p256_to_affine(&self, x: &P256FEle, y: &P256FEle, z: &P256FEle) -> (BigInt, BigInt) {
        let (mut xx, mut yy) = ([0u32; P256_LIMBS],[0u32; P256_LIMBS]);
        Self::p256_point_to_affine(&mut xx, &mut yy, x, y, z);
        (self.p256_to_bigint(&xx), self.p256_to_bigint(&yy))
    }
    
    fn p256_scalar_mult(xout: &mut P256FEle, yout: &mut P256FEle, zout: &mut P256FEle, x: &P256FEle, y: &P256FEle, scalar: &[u8;32]) {
        let (mut nisinfinitymask, mut index, mut pisnoninfinitemask, mut mask );
        let (mut px, mut py, mut pz, mut tx, mut ty,mut tz) = (
            [0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],
            );
        let mut precomp = [[[0u32; P256_LIMBS];3];16];

        // We precompute 0,1,2,... times {x,y}.
        precomp[1][0] = *x;
        precomp[1][1] = *y;
        precomp[1][2] = P256_ONE;

        for i in (2..16).step_by(2) {
            Self::p256_point_double_a(&mut precomp[i][0], &mut precomp[i][1], &mut precomp[i][2], &precomp[i/2][0], &precomp[i/2][1], &precomp[i/2][2]);
            Self::p256_point_add_mixed_a(&mut precomp[i+1][0], &mut precomp[i+1][1], &mut precomp[i+1][2], &precomp[i][0], &precomp[i][1], &precomp[i][2], x, y);
        }
        

        xout.iter_mut().zip(yout.iter_mut().zip(zout.iter_mut())).for_each(|(m, (n, l))| {
            *m = 0; *n = 0; *l = 0;
        });
        nisinfinitymask = !0u32;

        // We add in a window of four bits each iteration and do this 64 times.
        for i in 0..64 {
            if i != 0 {
                Self::p256_point_double_a(xout, yout, zout, xout, yout, zout);
                Self::p256_point_double_a(xout, yout, zout, xout, yout, zout);
                Self::p256_point_double_a(xout, yout, zout, xout, yout, zout);
                Self::p256_point_double_a(xout, yout, zout, xout, yout, zout);
            }

            index = scalar[31-(i/2)] as u32;
            if (i & 1) == 1 {
                index &= 15;
            } else {
                index >>= 4;
            }

            // See the comments in scalarBaseMult about handling infinities.
            Self::p256_select_jacobian_point(&mut px, &mut py, &mut pz, &precomp, index);
            Self::p256_point_add(&mut tx, &mut ty, &mut tz, xout, yout, zout, &px, &py, &pz);
            Self::p256_copy_conditional(xout, &px, nisinfinitymask);
            Self::p256_copy_conditional(yout, &py, nisinfinitymask);
            Self::p256_copy_conditional(zout, &pz, nisinfinitymask);

            pisnoninfinitemask = Self::non_zero_to_all_ones(index);
            mask = pisnoninfinitemask & (!nisinfinitymask);
            Self::p256_copy_conditional(xout, &tx, mask);
            Self::p256_copy_conditional(yout, &ty, mask);
            Self::p256_copy_conditional(zout, &tz, mask);
            nisinfinitymask &= !pisnoninfinitemask;
        }
    }
    
    fn p256_from_bigint(&self, out: &mut P256FEle, a: &BigInt) {
        let mut tmp = a.clone() << 257;
        tmp.rem_euclid_assign(self.cp.field_order().clone());
        
        let mut i = 0;
        
        while i < out.len() {
            let tmp_nat: &[u32] = tmp.as_ref().as_ref();
            out[i] = tmp_nat[0] & BOTTOM_29BITS;
            tmp >>= 29;
            
            i += 1;
            if i == P256_LIMBS {
                break;
            }
            let tmp_nat: &[u32] = tmp.as_ref().as_ref();
            out[i] = tmp_nat[0] & BOTTOM_28BITS;
            tmp >>= 28;
            i += 1;
        }
    }
}

impl EllipticCurve for CurveP256 {
    fn curve_params(&self) -> &CurveParams {
        &self.cp
    }

    fn is_on_curve(&self, x: &BigInt, y: &BigInt) -> bool {
        self.cp.is_on_curve(x, y)
    }

    fn add(&self, x1: &BigInt, y1: &BigInt, x2: &BigInt, y2: &BigInt) -> (BigInt, BigInt) {
        self.cp.add(x1, y1, x2, y2)
    }

    fn double(&self, x: &BigInt, y: &BigInt) -> (BigInt, BigInt) {
        self.cp.double(x, y)
    }

    fn scalar(&self, x: &BigInt, y: &BigInt, k: &Nat) -> (BigInt, BigInt) {
        if k.is_nan() || x.is_nan() || y.is_nan() {
            let tmp = Vec::new();
            return (BigInt::from_be_bytes(tmp.as_slice()), BigInt::from_be_bytes(tmp.as_slice()));
        }

        let mut scalar_reversed = [0u8; 32];
        self.p256_get_scalar(&mut scalar_reversed, k);

        let (mut x1, mut y1, mut z1) = ([0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],);
        let (mut px, mut py) = ([0u32; P256_LIMBS], [0u32; P256_LIMBS]);
        self.p256_from_bigint(&mut px, x);
        self.p256_from_bigint(&mut py, y);
        Self::p256_scalar_mult(&mut x1, &mut y1, &mut z1, &px, &py, &scalar_reversed);
        self.p256_to_affine(&x1, &y1, &z1)
    }

    fn scalar_base_point(&self, k: &Nat) -> (BigInt, BigInt) {
        if k.is_nan() {
            let tmp = Vec::new();
            return (BigInt::from_be_bytes(tmp.as_slice()), BigInt::from_be_bytes(tmp.as_slice()));
        }
        
        let mut scalar_reversed = [0u8; 32];
        self.p256_get_scalar(&mut scalar_reversed, k);
        
        let (mut x1, mut y1, mut z1) = ([0u32; P256_LIMBS],[0u32; P256_LIMBS],[0u32; P256_LIMBS],);
        Self::p256_scalar_base_mult(&mut x1, &mut y1, &mut z1, &scalar_reversed);
        
        self.p256_to_affine(&x1, &y1, &z1)
    }
}