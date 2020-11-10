//! This is a constant-time, 32-bit implementation of P224. See FIPS 186-4, 
//! section D.2.2.
//!
//! See https://www.imperialviolet.org/2010/12/04/ecc.html ([1]) for background.

use crate::elliptic::{CurveParams, EllipticCurve};
use rmath::bigint::{BigInt, Nat};
use crate::CryptoError;

const TWO_31P3: u32 = (1u32 << 31) + (1u32<<3);
const TWO_31M3: u32 = (1u32<<31) - (1u32<<3);
const TWO_31M15M3: u32 = (1u32<<31) - (1u32<<15) - (1u32<<3);
const TWO_63P35: u64 = (1u64<<63) + (1u64<<35);
const TWO_63M35: u64 = (1u64<<63) - (1u64 << 35);
const TWO_63M35M19: u64 = (1u64<<63) - (1u64<<35) - (1u64<<19);
const BOTTOM_28_BITS: u32 = 0xfffffff;

// p224ZeroModP31 is 0 mod p where bit 31 is set in all limbs so that we can
// subtract smaller amounts without underflow. See the section "Subtraction" in
// [1] for reasoning.
const P224_ZERO_MOD_P31: [u32; 8] = [TWO_31P3, TWO_31M3, TWO_31M3, TWO_31M15M3, TWO_31M3, TWO_31M3, TWO_31M3, TWO_31M3];

// p224ZeroModP63 is 0 mod p where bit 63 is set in all limbs. See the section
// "Subtraction" in [1] for why.
const P224_ZERO_MOD_P63: [u64;8] = [TWO_63P35, TWO_63M35, TWO_63M35, TWO_63M35, TWO_63M35M19, TWO_63M35, TWO_63M35, TWO_63M35];

// p224P is the order of the field, represented as a p224FieldElement.
const P224_P: [u32; 8] = [1, 0, 0, 0xffff000, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff];

type P224FieldElement = [u32; 8];
const PFE_DF: [u32; 8] = [0u32; 8];

/// LargeFieldElement also represents an element of the field. The limbs are
/// still spaced 28-bits apart and in little-endian order. So the limbs are at
/// 0, 28, 56, ..., 392 bits, each 64-bits wide.
type P224LargeFieldElement =  [u64;15];
const PLFE_DF: [u64; 15] = [0u64; 15];

/// FIPS 186-4, D.1.2.3 P-224 Curve  
/// GF(p), E: $y^2 \equiv x^3 - 3\cdot x + b \mod p$  
/// p.bits_len() = 224
pub struct CurveP224 {
    cp: CurveParams,
    gx: P224FieldElement,
    gy: P224FieldElement,
    b: P224FieldElement,
}

impl Clone for CurveP224 {
    fn clone(&self) -> Self {
        Self {
            cp: self.cp.clone(),
            gx: self.gx.clone(),
            gy: self.gy.clone(),
            b: self.b.clone(),
        }
    }
}

impl CurveP224 {
    pub fn new() -> Result<Self, CryptoError> {
        let cp = CurveParams::p224()?;
        let (mut gx, mut gy, mut b) = (PFE_DF, PFE_DF, PFE_DF);
        
        Self::p224_from_bigint(&mut gx, cp.base_point().0);
        Self::p224_from_bigint(&mut gy, cp.base_point().1);
        Self::p224_from_bigint(&mut b, cp.coefficient_b());
        
        Ok(
            Self {
                cp,
                gx,
                gy,
                b,
            }
        )
    }

    /// p224Mul computes *out = a*b
    ///
    /// a[i] < 2**29, b[i] < 2**30 (or vice versa)
    /// out[i] < 2**29
    fn p224_mul(out: &mut P224FieldElement, a: &P224FieldElement, b: &P224FieldElement, tmp: &mut P224LargeFieldElement) {
        tmp.iter_mut().for_each(|e| {*e=0;});
        
        for (i, &x) in a.iter().enumerate() {
            for (j, &y) in b.iter().enumerate() {
                tmp[i+j] = tmp[i+j].wrapping_add((x as u64) * (y as u64));
            }
        }
        
        Self::p224_reduce_large(out, tmp);
    }
    
    fn p224_mul_a(out: *mut P224FieldElement, a: *const P224FieldElement, b: *const P224FieldElement, tmp: *mut P224LargeFieldElement) {
        let (out, a, b, tmp) = unsafe {
            (&mut *out, &*a, &*b, &mut *tmp)
        };
        Self::p224_mul(out, a, b, tmp);
    }


    // Square computes *out = a*a
    ///
    /// a[i] < 2**29
    /// out[i] < 2**29
    fn p224_square(out: &mut P224FieldElement, a: &P224FieldElement, tmp: &mut P224LargeFieldElement) {
        tmp.iter_mut().for_each(|e| {*e = 0;});
        
        for (i, &x) in a.iter().enumerate() {
            for (j, &y) in a.iter().take(i+1).enumerate() {
                let r = (x as u64) * (y as u64);
                if i == j {
                    tmp[i+j] = tmp[i+j].wrapping_add(r);
                } else {
                    tmp[i+j] = tmp[i+j].wrapping_add(r << 1);
                }
            }
        }
        
        Self::p224_reduce_large(out, tmp);
    }

    fn p224_square_a(out: *mut P224FieldElement, a: *const P224FieldElement, tmp: *mut P224LargeFieldElement) {
        let (out, a, tmp) = unsafe {
            (&mut *out, &*a, &mut *tmp)
        };
        
        Self::p224_square(out, a, tmp);
    }

    fn p224_add(out: &mut P224FieldElement, a: &P224FieldElement, b: &P224FieldElement) {
        out.iter_mut().zip(a.iter().zip(b.iter())).for_each(|(z, (&x, &y))| {
            *z = x.wrapping_add(y);
        });
    }

    fn p224_add_a(out: *mut P224FieldElement, a: *const P224FieldElement, b: *const P224FieldElement) {
        let (out, a, b) = unsafe {
            (&mut *out, &*a, &*b)
        };
        Self::p224_add(out, a, b);
    }
    
    fn p224_sub(out: &mut P224FieldElement, a: &P224FieldElement, b: &P224FieldElement) {
        out.iter_mut().zip(a.iter().zip(P224_ZERO_MOD_P31.iter().zip(b.iter())))
            .for_each(|(z, (&x, (&p, &y)))| {
                *z = x.wrapping_add(p).wrapping_sub(y);
            })
    }

    fn p224_sub_a(out: *mut P224FieldElement, a: *const P224FieldElement, b: *const P224FieldElement) {
        let (out, a, b) = unsafe {
            (&mut *out, &*a, &*b)
        };
        
        Self::p224_sub(out, a, b);
    }

    /// ReduceLarge converts a p224LargeFieldElement to a p224FieldElement.
    ///
    /// in[i] < 2**62
    fn p224_reduce_large(out: &mut P224FieldElement, a: &mut P224LargeFieldElement) {
        a.iter_mut().zip(P224_ZERO_MOD_P63.iter()).for_each(|(x, &y)| {
            *x = (*x).wrapping_add(y);
        });

        // Eliminate the coefficients at 2**224 and greater.
        for i in (8usize..=14).rev() {
            a[i-8] = a[i-8].wrapping_sub(a[i]);
            a[i-5] = a[i-5].wrapping_add((a[i] & 0xffff) << 12);
            a[i-4] = a[i-4].wrapping_add(a[i] >> 16);
        }
        a[8] = 0;
        // in[0..8] < 2**64

        // As the values become small enough, we start to store them in |out|
        // and use 32-bit operations.
        for i in 1..8usize {
            a[i+1] = a[i+1].wrapping_add(a[i] >> 28);
            out[i] = (a[i] & (BOTTOM_28_BITS as u64)) as u32;
        }
        a[0] = a[0].wrapping_sub(a[8]);
        out[3] = out[3].wrapping_add(((a[8] & 0xffff) << 12) as u32);
        out[4] = out[4].wrapping_add(((a[8] >> 16) & 0xffffffff) as u32);
        // in[0] < 2**64
        // out[3] < 2**29
        // out[4] < 2**29
        // out[1,2,5..7] < 2**28

        out[0] = (a[0] & (BOTTOM_28_BITS as u64)) as u32;
        out[1] = out[1].wrapping_add(((a[0] >> 28) & (BOTTOM_28_BITS as u64)) as u32);
        out[2] = out[2].wrapping_add((a[0] >> 56) as u32);
        // out[0] < 2**28
        // out[1..4] < 2**29
        // out[5..7] < 2**28
    }

    /// Reduce reduces the coefficients of a to smaller bounds.
    ///
    /// On entry: a[i] < 2**31 + 2**30
    /// On exit: a[i] < 2**29
    fn p224_reduce(a: &mut P224FieldElement) {
        for i in 0..7 {
            a[i+1] = a[i+1].wrapping_add(a[i] >> 28);
            a[i] &= BOTTOM_28_BITS;
        }
        let top = a[7] >> 28;
        a[7] &= BOTTOM_28_BITS;

        // top < 2**4
        let mut mask = top;
        mask |= mask >> 2;
        mask |= mask >> 1;
        mask <<= 31;
        mask = ((mask as i32) >> 31) as u32;
        // Mask is all ones if top != 0, all zero otherwise

        a[0] = a[0].wrapping_sub(top);
        a[3] = a[3].wrapping_add(top << 12);

        // We may have just made a[0] negative but, if we did, then we must
        // have added something to a[3], this it's > 2**12. Therefore we can
        // carry down to a[0].
        a[3] = a[3].wrapping_sub(1 & mask);
        a[2] = a[2].wrapping_add(mask & ((1u32 << 28) - 1));
        a[1] = a[1].wrapping_add(mask & ((1u32 << 28) - 1));
        a[0] = a[0].wrapping_add(mask & (1u32 << 28));
    }
    
    fn p224_from_bigint(e: &mut P224FieldElement, n: &BigInt) {
        let bytes = n.to_be_bytes();
        let bytes = bytes.as_slice();
        
        let (o0, bytes) = Self::get_ls28bits_from_end(bytes, 0);
        let (o1, bytes) = Self::get_ls28bits_from_end(bytes, 4);
        let (o2, bytes) = Self::get_ls28bits_from_end(bytes, 0);
        let (o3, bytes) = Self::get_ls28bits_from_end(bytes, 4);
        let (o4, bytes) = Self::get_ls28bits_from_end(bytes, 0);
        let (o5, bytes) = Self::get_ls28bits_from_end(bytes, 4);
        let (o6, bytes) = Self::get_ls28bits_from_end(bytes, 0);
        let (o7, _bytes) = Self::get_ls28bits_from_end(bytes, 4);
        
        e[0] = o0; e[1] = o1; e[2] = o2; e[3] = o3; e[4] = o4;
        e[5] = o5; e[6]= o6; e[7] = o7;
    }

    /// get28BitsFromEnd returns the least-significant 28 bits from buf>>shift,
    /// where buf is interpreted as a big-endian number.
    fn get_ls28bits_from_end<'a>(mut buf: &'a [u8], shift: usize) -> (u32, &'a[u8]) {
        let mut ret = 0u32;
        
        for i in 0..4 {
            let (mut b, l) = (0u8, buf.len());
            if l > 0 {
                b = buf[l - 1];
                if i != 3 || shift == 4 {
                    buf = &buf[..(l-1)];
                }
            }
            
            ret |= ((b as u32) << (8 * i)) >> shift;
        }
        
        ret &= BOTTOM_28_BITS;
        (ret, buf)
    }
    
    fn p224_to_bigint(e: &P224FieldElement) -> BigInt {
        let mut buf = [0u8; 28];
        
        buf[27] = (e[0] & 0xff) as u8;
        buf[26] = ((e[0] >> 8) & 0xff) as u8;
        buf[25] = ((e[0] >> 16) & 0xff) as u8;
        buf[24] = (((e[0] >> 24) & 0x0f) | ((e[1]<<4)&0xf0)) as u8;

        buf[23] = ((e[1] >> 4) & 0xff) as u8;
        buf[22] = ((e[1] >> 12) & 0xff) as u8;
        buf[21] = ((e[1] >> 20) & 0xff) as u8;

        buf[20] = (e[2] & 0xff) as u8;
        buf[19] = ((e[2] >> 8) & 0xff) as u8;
        buf[18] = ((e[2] >> 16) & 0xff) as u8;
        buf[17] = (((e[2] >> 24) & 0x0f) | ((e[3]<<4)&0xf0)) as u8;

        buf[16] = ((e[3] >> 4) & 0xff) as u8;
        buf[15] = ((e[3] >> 12) & 0xff) as u8;
        buf[14] = ((e[3] >> 20) & 0xff) as u8;

        buf[13] = ((e[4]) & 0xff) as u8;
        buf[12] = ((e[4] >> 8) & 0xff) as u8;
        buf[11] = ((e[4] >> 16) & 0xff) as u8;
        buf[10] = (((e[4] >> 24) & 0x0f) | ((e[5]<<4)&0xf0)) as u8;

        buf[9] = ((e[5] >> 4) & 0xff) as u8;
        buf[8] = ((e[5] >> 12) & 0xff) as u8;
        buf[7] = ((e[5] >> 20) & 0xff) as u8;

        buf[6] = ((e[6]) & 0xff) as u8;
        buf[5] = ((e[6] >> 8) & 0xff) as u8;
        buf[4] = ((e[6] >> 16) & 0xff) as u8;
        buf[3] = (((e[6] >> 24) & 0x0f) | ((e[7]<<4)&0xf0)) as u8;

        buf[2] = ((e[7] >> 4) & 0xff) as u8;
        buf[1] = ((e[7] >> 12) & 0xff) as u8;
        buf[0] = ((e[7] >> 20) & 0xff) as u8;
        
        BigInt::from_be_bytes(buf.as_ref())
    }

    /// p224Invert calculates *out = in**-1 by computing in**(2**224 - 2**96 - 1),
    /// i.e. Fermat's little theorem.
    fn p224_invert(out: &mut P224FieldElement, a: &P224FieldElement) {
        let (mut f1, mut f2, mut f3, mut f4) = (PFE_DF, PFE_DF, PFE_DF, PFE_DF);
        let mut c = PLFE_DF;

        Self::p224_square(&mut f1, a, &mut c);    // 2
        Self::p224_mul_a(&mut f1, &f1, a, &mut c);  // 2**2 - 1
        Self::p224_square_a(&mut f1, &f1, &mut c);   // 2**3 - 2
        Self::p224_mul_a(&mut f1, &f1, a, &mut c);  // 2**3 - 1
        Self::p224_square(&mut f2, &f1, &mut c);   // 2**4 - 2
        Self::p224_square_a(&mut f2, &f2, &mut c);   // 2**5 - 4
        Self::p224_square_a(&mut f2, &f2, &mut c);   // 2**6 - 8
        Self::p224_mul_a(&mut f1, &f1, &f2, &mut c); // 2**6 - 1
        Self::p224_square(&mut f2, &f1, &mut c);   // 2**7 - 2
        (0..5).for_each(|_| {   // 2**12 - 2**6
            Self::p224_square_a(&mut f2, &f2, &mut c);
        });
        Self::p224_mul_a(&mut f2, &f2, &f1, &mut c); // 2**12 - 1
        Self::p224_square(&mut f3, &f2, &mut c);   // 2**13 - 2
        (0..11).for_each(|_|{  // 2**24 - 2**12
            Self::p224_square_a(&mut f3, &f3, &mut c);
        });
        Self::p224_mul_a(&mut f2, &f3, &f2, &mut c); // 2**24 - 1
        Self::p224_square(&mut f3, &f2, &mut c);   // 2**25 - 2
        (0..23).for_each(|_| {  // 2**48 - 2**24
            Self::p224_square_a(&mut f3, &f3, &mut c);
        });
        Self::p224_mul_a(&mut f3, &f3, &f2, &mut c); // 2**48 - 1
        Self::p224_square(&mut f4, &f3, &mut c);   // 2**49 - 2
        (0..47).for_each(|_|{  // 2**96 - 2**48
            Self::p224_square_a(&mut f4, &f4, &mut c);
        });
        Self::p224_mul_a(&mut f3, &f3, &f4, &mut c); // 2**96 - 1
        Self::p224_square(&mut f4, &f3, &mut c);   // 2**97 - 2
        (0..23).for_each(|_|{  // 2**120 - 2**24
            Self::p224_square_a(&mut f4, &f4, &mut c);
        });
        Self::p224_mul_a(&mut f2, &f4, &f2, &mut c); // 2**120 - 1
        (0..6).for_each(|_|{   // 2**126 - 2**6
            Self::p224_square_a(&mut f2, &f2, &mut c);
        });
        Self::p224_mul_a(&mut f1, &f1, &f2, &mut c); // 2**126 - 1
        Self::p224_square_a(&mut f1, &f1, &mut c);   // 2**127 - 2
        Self::p224_mul_a(&mut f1, &f1, a, &mut c);  // 2**127 - 1
        (0..97).for_each(|_|{  // 2**224 - 2**97
            Self::p224_square_a(&mut f1, &f1, &mut c);
        });
        Self::p224_mul(out, &f1, &f3, &mut c); // 2**224 - 2**96 - 1
    }
    
    fn p224_contract_a(out: *mut P224FieldElement, a: *const P224FieldElement) {
        let (out, a) = unsafe {
            (&mut *out, &*a)
        };
        Self::p224_contract(out, a);
    }

    /// p224Contract converts a FieldElement to its unique, minimal form.
    ///
    /// On entry, in[i] < 2**29
    /// On exit, in[i] < 2**28
    fn p224_contract(out: &mut P224FieldElement, a: &P224FieldElement) {
        out.iter_mut().zip(a.iter()).for_each(|(x, &y)| {*x = y;});

        for i in 0..7 {
            out[i+1] = out[i+1].wrapping_add(out[i] >> 28);
            out[i] &= BOTTOM_28_BITS;
        }
        let top = out[7] >> 28;
        out[7] &= BOTTOM_28_BITS;

        out[0] = out[0].wrapping_sub(top);
        out[3] = out[3].wrapping_add(top << 12);

        // We may just have made out[i] negative. So we carry down. If we made
        // out[0] negative then we know that out[3] is sufficiently positive
        // because we just added to it.
        (0..3).for_each(|i| {
            let mask = ((out[i] as i32) >> 31) as u32;
            out[i] = out[i].wrapping_add((1 << 28) & mask);
            out[i+1] = out[i+1].wrapping_sub(1 & mask);
        });

        // We might have pushed out[3] over 2**28 so we perform another, partial,
        // carry chain.
        (3..7).for_each(|i| {
            out[i+1] = out[i+1].wrapping_add(out[i] >> 28);
            out[i] &= BOTTOM_28_BITS;
        });
        let top = out[7] >> 28;
        out[7] &= BOTTOM_28_BITS;

        // Eliminate top while maintaining the same value mod p.
        out[0] = out[0].wrapping_sub(top);
        out[3] = out[3].wrapping_add(top << 12);

        // There are two cases to consider for out[3]:
        //   1) The first time that we eliminated top, we didn't push out[3] over
        //      2**28. In this case, the partial carry chain didn't change any values
        //      and top is zero.
        //   2) We did push out[3] over 2**28 the first time that we eliminated top.
        //      The first value of top was in [0..16), therefore, prior to eliminating
        //      the first top, 0xfff1000 <= out[3] <= 0xfffffff. Therefore, after
        //      overflowing and being reduced by the second carry chain, out[3] <=
        //      0xf000. Thus it cannot have overflowed when we eliminated top for the
        //      second time.

        // Again, we may just have made out[0] negative, so do the same carry down.
        // As before, if we made out[0] negative then we know that out[3] is
        // sufficiently positive.
        (0..3).for_each(|i| {
            let mask = ((out[i] as i32) >> 31) as u32;
            out[i] = out[i].wrapping_add((1 << 28) & mask);
            out[i+1] = out[i+1].wrapping_sub(1 & mask);
        });

        // Now we see if the value is >= p and, if so, subtract p.

        // First we build a mask from the top four limbs, which must all be
        // equal to bottom28Bits if the whole value is >= p. If top4AllOnes
        // ends up with any zero bits in the bottom 28 bits, then this wasn't
        // true.
        let mut top4_all_ones = 0xffffffffu32;
        out.iter().skip(4).take(4).for_each(|&e| {
            top4_all_ones &= e;
        });
        top4_all_ones |= 0xf0000000;
        // Now we replicate any zero bits to all the bits in top4_all_ones.
        top4_all_ones &= top4_all_ones >> 16;
        top4_all_ones &= top4_all_ones >> 8;
        top4_all_ones &= top4_all_ones >> 4;
        top4_all_ones &= top4_all_ones >> 2;
        top4_all_ones &= top4_all_ones >> 1;
        top4_all_ones = (((top4_all_ones << 31) as i32) >> 31) as u32;

        // Now we test whether the bottom three limbs are non-zero.
        let mut bottom3_non_zero = out[0] | out[1] | out[2];
        bottom3_non_zero |= bottom3_non_zero >> 16;
        bottom3_non_zero |= bottom3_non_zero >> 8;
        bottom3_non_zero |= bottom3_non_zero >> 4;
        bottom3_non_zero |= bottom3_non_zero >> 2;
        bottom3_non_zero |= bottom3_non_zero >> 1;
        bottom3_non_zero = (((bottom3_non_zero << 31) as i32) >> 31) as u32;

        // Everything depends on the value of out[3].
        //    If it's > 0xffff000 and top4AllOnes != 0 then the whole value is >= p
        //    If it's = 0xffff000 and top4AllOnes != 0 and bottom3NonZero != 0,
        //      then the whole value is >= p
        //    If it's < 0xffff000, then the whole value is < p
        let n = out[3].wrapping_sub( 0xffff000);
        let mut out3_equal = n;
        out3_equal |= out3_equal >> 16;
        out3_equal |= out3_equal >> 8;
        out3_equal |= out3_equal >> 4;
        out3_equal |= out3_equal >> 2;
        out3_equal |= out3_equal >> 1;
        out3_equal = !((((out3_equal << 31) as i32) >> 31) as u32);

        // If out[3] > 0xffff000 then n's MSB will be zero.
        let out3_gt = !(((n as i32) >> 31) as u32);

        let mask = top4_all_ones & ((out3_equal & bottom3_non_zero) | out3_gt);
        out[0] = out[0].wrapping_sub(1 & mask);
        out[3] = out[3].wrapping_sub(0xffff000 & mask);
        out[4] = out[4].wrapping_sub(0xfffffff & mask);
        out[5] = out[5].wrapping_sub(0xfffffff & mask);
        out[6] = out[6].wrapping_sub(0xfffffff & mask);
        out[7] = out[7].wrapping_sub(0xfffffff & mask);
    }
    
    fn p224_copy_conditional(out: &mut P224FieldElement, a: &P224FieldElement, mut control: u32) {
        control <<= 31;
        control = ((control as i32) >> 31) as u32;
        out.iter_mut().zip(a.iter()).for_each(|(x, &y)| {
            *x ^= ((*x) ^ y) & control;
        });
    }

    /// p224IsZero returns 1 if a == 0 mod p and 0 otherwise.
    ///
    /// a[i] < 2**29
    fn p224_is_zero(a: &P224FieldElement) -> u32 {
        // Since a p224FieldElement contains 224 bits there are two possible
        // representations of 0: 0 and p.
        let mut minimal = PFE_DF;
        Self::p224_contract(&mut minimal, a);

        let (mut is_zero, mut is_p) = (0u32, 0u32);
        minimal.iter().zip(P224_P.iter()).for_each(|(&v, &p)| {
            is_zero  |= v;
            is_p |= v.wrapping_sub(p);
        });

        // If either isZero or isP is 0, then we should return 1.
        is_zero |= is_zero >> 16;
        is_zero |= is_zero >> 8;
        is_zero |= is_zero >> 4;
        is_zero |= is_zero >> 2;
        is_zero |= is_zero >> 1;

        is_p |= is_p >> 16;
        is_p |= is_p >> 8;
        is_p |= is_p >> 4;
        is_p |= is_p >> 2;
        is_p |= is_p >> 1;

        // For isZero and isP, the LSB is 0 iff all the bits are zero.
        let result = is_zero & is_p;
        (!result) & 1
    }
    
    fn p224_scalar_mult(x1: &mut P224FieldElement, y1: &mut P224FieldElement, z1: &mut P224FieldElement, x0: &P224FieldElement, y0: &P224FieldElement, z0: &P224FieldElement, scalar: &[u8]) {
        let (mut xx, mut yy, mut zz) = (PFE_DF,PFE_DF,PFE_DF);
        x1.iter_mut().zip(y1.iter_mut().zip(z1.iter_mut())).for_each(|(p, (q, r))| {
            *p = 0; *q = 0; *r = 0;
        });
        
        for &byte in scalar.iter() {
            for bitnum in 0..8 {
                Self::p224_double_jacobian_a(x1, y1, z1, x1, y1, z1);
                let bit = ((byte >> (7 - bitnum)) & 1) as u32;
                Self::p224_add_jacobian(&mut xx, &mut yy, &mut zz, x0, y0, z0, x1, y1, z1);
                Self::p224_copy_conditional(x1, &xx, bit);
                Self::p224_copy_conditional(y1, &yy, bit);
                Self::p224_copy_conditional(z1, &zz, bit);
            }
        }
    } 
    
    fn p224_to_affine(x: &mut P224FieldElement, y: &mut P224FieldElement, z: &mut P224FieldElement) -> (BigInt, BigInt) {
        let (mut zinv, mut zinvsq, mut outx, mut outy) = (PFE_DF, PFE_DF, PFE_DF, PFE_DF);
        let mut tmp = PLFE_DF;

        if Self::p224_is_zero(z) == 1 {
            return (BigInt::from(0u32), BigInt::from(0u32));
        }

        Self::p224_invert(&mut zinv, z);
        Self::p224_square(&mut zinvsq, &zinv, &mut tmp);
        Self::p224_mul_a(x, x, &zinvsq, &mut tmp);
        Self::p224_mul_a(&mut zinvsq, &zinvsq, &zinv, &mut tmp);
        Self::p224_mul_a(y, y, &zinvsq, &mut tmp);

        Self::p224_contract(&mut outx, &*x);
        Self::p224_contract(&mut outy, &*y);
        (Self::p224_to_bigint(&outx), Self::p224_to_bigint(&outy))
    }

    /// Group element functions.
    ///
    /// These functions deal with group elements. The group is an elliptic curve
    /// group with a = -3 defined in FIPS 186-4, section D.2.2.
    /// p224AddJacobian computes *out = a+b where a != b.
    fn p224_add_jacobian(x3: &mut P224FieldElement, y3: &mut P224FieldElement, z3: &mut P224FieldElement,
        x1: &P224FieldElement, y1: &P224FieldElement, z1: &P224FieldElement, x2: &P224FieldElement, y2: &P224FieldElement, z2: &P224FieldElement) {
        let (mut z1z1, mut z2z2, mut u1, mut u2, mut s1, mut s2, mut h, mut i, mut j, mut r, mut v) = (
            PFE_DF,PFE_DF,PFE_DF,PFE_DF,PFE_DF,PFE_DF,PFE_DF,PFE_DF,PFE_DF,PFE_DF,PFE_DF,
            );
        let mut c = PLFE_DF;

        let (z1_is_zero, z2_is_zero) = (Self::p224_is_zero(z1), Self::p224_is_zero(z2));

        // Z1Z1 = Z1²
        Self::p224_square(&mut z1z1, z1, &mut c);
        // Z2Z2 = Z2²
        Self::p224_square(&mut z2z2, z2, &mut c);
        // U1 = X1*Z2Z2
        Self::p224_mul(&mut u1, x1, &z2z2, &mut c);
        // U2 = X2*Z1Z1
        Self::p224_mul(&mut u2, x2, &z1z1, &mut c);
        // S1 = Y1*Z2*Z2Z2
        Self::p224_mul(&mut s1, z2, &z2z2, &mut c);
        Self::p224_mul_a(&mut s1, y1, &s1, &mut c);
        // S2 = Y2*Z1*Z1Z1
        Self::p224_mul(&mut s2, z1, &z1z1, &mut c);
        Self::p224_mul_a(&mut s2, y2, &s2, &mut c);
        // H = U2-U1
        Self::p224_sub(&mut h, &u2, &u1);
        Self::p224_reduce(&mut h);
        let x_equal = Self::p224_is_zero(&h);
        // I = (2*H)²
        i.iter_mut().zip(h.iter()).for_each(|(m, &n)| {
            *m = n << 1;
        });
        Self::p224_reduce(&mut i);
        Self::p224_square_a(&mut i, &i, &mut c);
        // J = H*I
        Self::p224_mul(&mut j, &h, &i, &mut c);
        // r = 2*(S2-S1)
        Self::p224_sub(&mut r, &s2, &s1);
        Self::p224_reduce(&mut r);
        let y_equal = Self::p224_is_zero(&mut r);
        if x_equal == 1 && y_equal == 1 && z1_is_zero == 0 && z2_is_zero == 0 {
            Self::p224_double_jacobian(x3, y3, z3, x1, y1, z1);
            return;
        }
        r.iter_mut().for_each(|m| {*m <<= 1;});
        Self::p224_reduce(&mut r);
        // V = U1*I
        Self::p224_mul(&mut v, &u1, &i, &mut c);
        // Z3 = ((Z1+Z2)²-Z1Z1-Z2Z2)*H
        Self::p224_add_a(&mut z1z1, &z1z1, &z2z2);
        Self::p224_add(&mut z2z2, z1, z2);
        Self::p224_reduce(&mut z2z2);
        Self::p224_square_a(&mut z2z2,&z2z2, &mut c);
        Self::p224_sub(z3, &z2z2, &z1z1);
        Self::p224_reduce(z3);
        Self::p224_mul_a(z3, z3, &h, &mut c);
        // X3 = r²-J-2*V
        z1z1.iter_mut().zip(v.iter()).for_each(|(m, &n)| {*m = n << 1;});
        Self::p224_add_a(&mut z1z1, &j, &z1z1);
        Self::p224_reduce(&mut z1z1);
        Self::p224_square(x3, &r, &mut c);
        Self::p224_sub_a(x3, x3, &z1z1);
        Self::p224_reduce(x3);
        // Y3 = r*(V-X3)-2*S1*J
        s1.iter_mut().for_each(|m| {
            *m <<= 1;
        });
        Self::p224_mul_a(&mut s1, &s1, &j, &mut c);
        Self::p224_sub(&mut z1z1, &v, &*x3);
        Self::p224_reduce(&mut z1z1);
        Self::p224_mul_a(&mut z1z1, &z1z1, &r, &mut c);
        Self::p224_sub(y3, &z1z1, &s1);
        Self::p224_reduce(y3);

        Self::p224_copy_conditional(x3, x2, z1_is_zero);
        Self::p224_copy_conditional(x3, x1, z2_is_zero);
        Self::p224_copy_conditional(y3, y2, z1_is_zero);
        Self::p224_copy_conditional(y3, y1, z2_is_zero);
        Self::p224_copy_conditional(z3, z2, z1_is_zero);
        Self::p224_copy_conditional(z3, z1, z2_is_zero);
    }
    
    fn p224_double_jacobian_a(x3: *mut P224FieldElement, y3: *mut P224FieldElement, z3: *mut P224FieldElement, x1: *const P224FieldElement, y1: *const P224FieldElement, z1: *const P224FieldElement) {
        let (x3, y3, z3, x1, y1, z1) = unsafe {
            (&mut *x3, &mut *y3, &mut *z3, &*x1, &*y1, &*z1)
        };
        Self::p224_double_jacobian(x3, y3, z3, x1, y1, z1);
    }
    
    fn p224_double_jacobian(x3: &mut P224FieldElement, y3: &mut P224FieldElement, z3: &mut P224FieldElement, x1: &P224FieldElement, y1: &P224FieldElement, z1: &P224FieldElement) {
        let (mut delta, mut gamma, mut beta, mut alpha, mut t) = (PFE_DF, PFE_DF, PFE_DF, PFE_DF, PFE_DF);
        let mut c = PLFE_DF;


        Self::p224_square(&mut delta, z1, &mut c);
        Self::p224_square(&mut gamma, y1, &mut c);
        Self::p224_mul(&mut beta, x1, &gamma, &mut c);

        // alpha = 3*(X1-delta)*(X1+delta)
        Self::p224_add(&mut t, x1, &delta);
        t.iter_mut().for_each(|x| {
            *x = (*x).wrapping_add((*x) << 1);
        });
        Self::p224_reduce(&mut t);
        Self::p224_sub(&mut alpha, x1, &delta);
        Self::p224_reduce(&mut alpha);
        Self::p224_mul_a(&mut alpha, &alpha, &t, &mut c);

        // Z3 = (Y1+Z1)²-gamma-delta
        Self::p224_add(z3, y1, z1);
        Self::p224_reduce(z3);
        Self::p224_square_a(z3, z3, &mut c);
        Self::p224_sub_a(z3, z3, &gamma);
        Self::p224_reduce(z3);
        Self::p224_sub_a(z3, z3, &delta);
        Self::p224_reduce(z3);

        // X3 = alpha²-8*beta
        delta.iter_mut().zip(beta.iter()).for_each(|(x, &y)| {
            *x = y << 3;
        });
        Self::p224_reduce(&mut delta);
        Self::p224_square(x3, &alpha, &mut c);
        Self::p224_sub_a(x3,x3, &delta);
        Self::p224_reduce(x3);

        // Y3 = alpha*(4*beta-X3)-8*gamma²
        beta.iter_mut().for_each(|x| {
            *x <<= 2;
        });
        Self::p224_sub_a(&mut beta, &beta, &*x3);
        Self::p224_reduce(&mut beta);
        Self::p224_square_a(&mut gamma, &gamma, &mut c);
        gamma.iter_mut().for_each(|x| {
            *x <<= 3;
        });
        Self::p224_reduce(&mut gamma);
        Self::p224_mul(y3, &alpha, &beta, &mut c);
        Self::p224_sub_a(y3,y3, &gamma);
        Self::p224_reduce(y3);
    }
}

impl EllipticCurve for CurveP224 {
    fn curve_params(&self) -> &CurveParams {
        &self.cp
    }

    fn is_on_curve(&self, x: &BigInt, y: &BigInt) -> bool {
        if x.is_nan() || y.is_nan() {
            return false;
        }
        let (mut a, mut b) = (PFE_DF, PFE_DF);
        Self::p224_from_bigint(&mut a, x);
        Self::p224_from_bigint(&mut b, y);

        // y² = x³ - 3x + b
        let mut tmp = PLFE_DF;
        let mut x3 = PFE_DF;
        Self::p224_square(&mut x3, &a, &mut tmp);
        Self::p224_mul_a(&mut x3, &x3, &a, &mut tmp);

        a.iter_mut().for_each(|m| {*m = (*m).wrapping_mul(3);});
        Self::p224_sub_a(&mut x3, &x3, &a);
        Self::p224_reduce(&mut x3);
        Self::p224_add_a(&mut x3, &x3, &self.b);
        Self::p224_contract_a(&mut x3, &x3);

        Self::p224_square_a(&mut b, &b, &mut tmp);
        Self::p224_contract_a(&mut b, &b);

        for (&m, &n) in x3.iter().zip(b.iter()) {
            if m != n {
                return false;
            }
        }
        
        true
    }

    fn add(&self, x1: &BigInt, y1: &BigInt, x2: &BigInt, y2: &BigInt) -> (BigInt, BigInt) {
        if x1.is_nan() || y1.is_nan() || x2.is_nan() || y2.is_nan() {
            let tmp = Vec::new();
            return (BigInt::from_be_bytes(tmp.as_slice()), BigInt::from_be_bytes(tmp.as_slice()));
        }
        
        let (mut a1, mut b1, mut c1, mut a2, mut b2, mut c2, mut a3, mut b3, mut c3) = (
            PFE_DF, PFE_DF,PFE_DF,PFE_DF,PFE_DF,PFE_DF,PFE_DF,PFE_DF,PFE_DF,
            );
        Self::p224_from_bigint(&mut a1, x1);
        Self::p224_from_bigint(&mut b1, y1);
        if x1.signnum() != Some(0) || y1.signnum() != Some(0) {
            c1[0] = 1;
        }
        
        Self::p224_from_bigint(&mut a2, x2);
        Self::p224_from_bigint(&mut b2, y2);
        if x2.signnum() != Some(0) || y2.signnum() != Some(0) {
            c2[0] = 1;
        }
        
        Self::p224_add_jacobian(&mut a3, &mut b3, &mut c3, &a1, &b1, &c1, &a2, &b2, &c2);
        Self::p224_to_affine(&mut a3, &mut b3, &mut c3)
    }

    fn double(&self, x: &BigInt, y: &BigInt) -> (BigInt, BigInt) {
        if x.is_nan() || y.is_nan() {
            let tmp = Vec::new();
            return (BigInt::from_be_bytes(tmp.as_slice()), BigInt::from_be_bytes(tmp.as_slice()));
        }
        
        let (mut a1, mut b1, mut c1, mut a2, mut b2, mut c2) = (
            PFE_DF,PFE_DF,PFE_DF,PFE_DF,PFE_DF,PFE_DF,
            );
        Self::p224_from_bigint(&mut a1, x);
        Self::p224_from_bigint(&mut b1, y);
        c1[0] = 1;
        Self::p224_double_jacobian(&mut a2, &mut b2, &mut c2, &a1, &b1, &c1);
        Self::p224_to_affine(&mut a2, &mut b2, &mut c2)
    }

    fn scalar(&self, x: &BigInt, y: &BigInt, k: &Nat) -> (BigInt, BigInt) {
        if x.is_nan() || y.is_nan() || k.is_nan() {
            let tmp = Vec::new();
            return (BigInt::from_be_bytes(tmp.as_slice()), BigInt::from_be_bytes(tmp.as_slice()));
        }
        
        let (mut a1, mut b1, mut c1, mut a2, mut b2, mut c2) = (
            PFE_DF,PFE_DF,PFE_DF,PFE_DF,PFE_DF,PFE_DF,
        );
        Self::p224_from_bigint(&mut a1, x);
        Self::p224_from_bigint(&mut b1, y);
        c1[0] = 1;
        let scalar = k.to_be_bytes();
        Self::p224_scalar_mult(&mut a2, &mut b2, &mut c2, &a1, &b1, &c1, scalar.as_slice());
        Self::p224_to_affine(&mut a2, &mut b2, &mut c2)
    }

    fn scalar_base_point(&self, k: &Nat) -> (BigInt, BigInt) {
        if k.is_nan() {
            let tmp = Vec::new();
            return (BigInt::from_be_bytes(tmp.as_slice()), BigInt::from_be_bytes(tmp.as_slice()));
        }
        
        let (mut z1, mut x2, mut y2, mut z2) = (PFE_DF, PFE_DF, PFE_DF, PFE_DF, );
        z1[0] = 1;
        let scalar = k.to_be_bytes();
        Self::p224_scalar_mult(&mut x2, &mut y2, &mut z2, &self.gx, &self.gy, &z1, scalar.as_slice());
        Self::p224_to_affine(&mut x2, &mut y2, &mut z2)
    }
}