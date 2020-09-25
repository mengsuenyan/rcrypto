//! [KECCAK](keccak.noekeon.org)  
//! 
//! SHA-3: FIPS-202  
//! 
//! https://www.cnblogs.com/mengsuenyan/p/13182759.html  

use crate::{CryptoError, CryptoErrorKind};
use std::ops::{Index, IndexMut};
use crate::crypto_err::CryptoErrorKind::InvalidParameter;

// Keccak-p[b] where $b=25*w, w=2^l, l\in [0,6]$
const KECCAK_PERMUTATION_WIDTHS: [usize; 7] = [
    25, 50, 100, 200, 400, 800, 1600
];

const KECCAK_X_SIZE: usize = 5;
const KECCAK_Y_SIZE: usize = 5;
const KECCAK_Z_SIZE: usize = 64; // 2^l, l = (0..6).max()

/// state array, A[x,y,z] = S[w(5y+x)+z]
#[derive(Clone)]
struct KeccakStateArr {
    state: [[[u8; KECCAK_Z_SIZE]; KECCAK_Y_SIZE]; KECCAK_X_SIZE],
}

impl KeccakStateArr {
    /// reset state array to the initial state
    fn reset(&mut self) {
        self.state = [[[0; KECCAK_Z_SIZE]; KECCAK_Y_SIZE]; KECCAK_X_SIZE];
    }
    
    fn cvt_from_slice(&mut self, s: &[u8], w: usize) {
        self.state.iter_mut().enumerate().for_each(|(x, sheet)| {
            sheet.iter_mut().enumerate().for_each(|(y, lane)| {
                lane.iter_mut().take(w).enumerate().for_each(|(z, e)| {
                    let idx = (w * ((KECCAK_Y_SIZE * y) + x)) + z;
                    let (num, rom) = (idx >> 3, 7 - (idx & 7));
                    let tmp = s[s.len() - num - 1];
                    *e = (tmp >> rom) & 1;
                });
            });
        });
    }

    /// b0b1b2b3b4b5b6b7   
    /// hex = b7*2^7 + b6*2^6 + ... + b0*2^0   
    fn cvt_to_slice(res: &mut Vec<u8>) {
        let len = res.len() >> 3;
        for i in 0..len {
            let si = i << 3;
            res[i] = res[si] | (res[si+1] << 1) | (res[si+2] << 2) | (res[si+3] << 3) | (res[si+4] << 4) |
                (res[si+5] << 5) | (res[si+6] << 6) | (res[si+7] << 7);
        }
        
        let (len2, mut tmp) = (len << 3, 0);
        for j in len2..res.len() {
            tmp |= res[j] << (j-len2);
        }
        
        if len2 < res.len() {
            res[len] = tmp;
            res.truncate(len + 1);
        } else {
            res.truncate(len);
        }
    }
    
    fn finish(&self, s: &mut Vec<u8>, w: usize) {
        for y in 0..KECCAK_Y_SIZE {
            for x in 0..KECCAK_X_SIZE {
                for z in 0..w {
                    s.push(self.state[x][y][z]);
                }
            }
        }
    }
}

impl Default for KeccakStateArr {
    fn default() -> Self {
        Self {
            state: [[[0; KECCAK_Z_SIZE]; KECCAK_Y_SIZE]; KECCAK_X_SIZE],
        }
    }
}

impl Index<(usize, usize, usize)> for KeccakStateArr {
    type Output = u8;

    fn index(&self, index: (usize, usize, usize)) -> &Self::Output {
        // (x,y,z)
        &self.state[index.0][index.1][index.2]
    }
}

impl IndexMut<(usize, usize, usize)> for KeccakStateArr {
    fn index_mut(&mut self, index: (usize, usize, usize)) -> &mut Self::Output {
        // (x,y,z)
        &mut self.state[index.0][index.1][index.2]
    }
}

#[derive(Clone)]
pub struct Keccak {
    // the width of the permutation that the value in the KECCAK_PERMUTATION_WIDTHS
    b: usize,
    w: usize,
    l: usize,
    // the number of rounds
    nr: i64,
    buf0: KeccakStateArr,
    buf1: KeccakStateArr,
    // false: buf0, true: buf1
    state_flag: bool,
}

struct KeccakBufGuard<'a> {
    input: &'a mut KeccakStateArr,
    output: &'a mut KeccakStateArr,
    state_flag: &'a mut bool,
}

impl<'a> KeccakBufGuard<'a> {
    fn new(keccak: &'a mut Keccak) -> Self {
        if keccak.state_flag {
            Self {
                input: &mut keccak.buf1,
                output: &mut keccak.buf0,
                state_flag: &mut keccak.state_flag,
            }
        } else {
            Self {
                input: &mut keccak.buf0,
                output: &mut keccak.buf1,
                state_flag: &mut keccak.state_flag,
            }
        }
    }
}

impl<'a> Drop for KeccakBufGuard<'a> {
    fn drop(&mut self) {
        *self.state_flag = !(*self.state_flag);
    }
}

macro_rules! impl_keccak_width {
    ($W: literal, $FN: ident, $PN: ident) => {
        pub fn $FN($PN: u32) -> Self {
            Self::new($W, $PN).unwrap()
        }
    };
}

impl Keccak {
    /// KECCAK-p[b,nr]  
    /// b means that the width of the permutation;  
    /// nr means that the number of rounds; 
    pub fn new(b: usize, nr: u32) -> std::result::Result<Keccak, CryptoError> {
        if KECCAK_PERMUTATION_WIDTHS.iter().fold(false, |is_checked, &e| {
            if is_checked || e == b {
                true
            } else {
                false
            }
        }) {
            Ok(
                Self {
                    b,
                    nr: nr as i64,
                    w: b / 25,
                    l: (b/25).trailing_zeros() as usize,
                    buf0: KeccakStateArr::default(),
                    buf1: KeccakStateArr::default(),
                    state_flag: false,
                }
            )
        } else {
            Err(CryptoError::new(CryptoErrorKind::InvalidParameter, 
                format!("Wrong b({}), the width of the permutation must belong to the {:?}", b, KECCAK_PERMUTATION_WIDTHS)))
        }
    }

    impl_keccak_width!(25, keccak_25, nr);
    impl_keccak_width!(50, keccak_50, nr);
    impl_keccak_width!(100, keccak_100, nr);
    impl_keccak_width!(200, keccak_200, nr);
    impl_keccak_width!(400, keccak_400, nr);
    impl_keccak_width!(800, keccak_800, nr);
    impl_keccak_width!(1600, keccak_1600, nr);
    
    /// (lhs-rhs) % modulus
    #[inline]
    fn minus_rem_euclid(lhs: usize, rhs: usize, modulus: usize) -> usize {
        if lhs < rhs {
            let tmp = (rhs - lhs) % modulus;
            if tmp > 0 {
                modulus - tmp
            } else {
                0
            }
        } else {
            (lhs - rhs) % modulus
        }
    }
    
    /// step mapping: $\theta(A) \rightarrow A^'$
    fn theta(&mut self) {
        let w = self.w;
        let state = KeccakBufGuard::new(self);
        let mut c = [[0u8; KECCAK_Z_SIZE]; KECCAK_X_SIZE];
        for x in 0..KECCAK_X_SIZE {
            for z in 0..w {
                c[x][z] = state.input[(x,0,z)] ^ state.input[(x,1,z)] ^ state.input[(x,2,z)] ^ 
                    state.input[(x,3,z)] ^ state.input[(x,4,z)];
            }
        }
        
        let mut d = [[0u8; KECCAK_Z_SIZE]; KECCAK_X_SIZE];
        for x in 0..KECCAK_X_SIZE {
            for z in 0..w {
                d[x][z] = c[if x < 1 {KECCAK_X_SIZE-1} else {(x-1) % KECCAK_X_SIZE}][z] ^ 
                    c[(x+1) % KECCAK_X_SIZE][if z < 1 {w-1} else {(z-1)%w}];
            }
        }
        
        for y in 0..KECCAK_Y_SIZE {
            for x in 0..KECCAK_X_SIZE {
                for z in 0..w {
                    state.output[(x,y,z)] = state.input[(x,y,z)] ^ d[x][z];
                }
            }
        }
    }
    
    /// step mapping: $\rho(A) \rightarrow A^'$
    fn rho(&mut self) {
        let w = self.w;
        let state = KeccakBufGuard::new(self);
        
        for z in 0..w {
            state.output[(0,0,z)] = state.input[(0,0,z)];
        }
        
        let (mut x, mut y) = (1,0);
        for t in 0..=23 {
            for z in 0..w {
                state.output[(x, y, z)] = state.input[(x, y, Self::minus_rem_euclid(z, (t+1)*(t+2)/2, w))]
            }
            let tmp = x;
            x = y;
            y = (2 * tmp + 3 * y) % KECCAK_Y_SIZE;
        }
    }
    
    /// step mapping: $\pi(A) \rightarrow A^'$
    fn pi(&mut self) {
        let w = self.w;
        let state = KeccakBufGuard::new(self);
        
        for x in 0..KECCAK_X_SIZE {
            for y in 0..KECCAK_Y_SIZE {
                for z in 0..w {
                    state.output[(x,y,z)] = state.input[((x+3*y)%KECCAK_X_SIZE,x,z)];
                }
            }
        }
    }
    
    /// step mapping: $\chi(A) \rightarrow A^'$
    fn chi(&mut self) {
        let w = self.w;
        let state = KeccakBufGuard::new(self);

        for x in 0..KECCAK_X_SIZE {
            for y in 0..KECCAK_Y_SIZE {
                for z in 0..w {
                    state.output[(x,y,z)] = state.input[(x,y,z)] ^ (
                        (state.input[((x+1)%KECCAK_X_SIZE,y,z)] ^ 1) & state.input[((x+2)%KECCAK_X_SIZE,y,z)]
                        );
                }
            }
        }
    }
    
    fn rc(t: i64) -> u8 {
        const MODULUS: usize = 255;
        let t = if t >= 0 {Self::minus_rem_euclid((t & 0xffffffff) as usize,0, MODULUS)}
            else {Self::minus_rem_euclid(0, (t & 0xffffffff) as usize, MODULUS)};
        
        if t == 0 {
            1
        } else {
            const INIT_IDX: usize = 7;
            let mut r = [0u8; INIT_IDX+MODULUS];
            r[INIT_IDX] = 1;
            for i in (INIT_IDX+1)..=(INIT_IDX + t) {
                r[i] = r[i] ^ r[i-8];
                r[i-4] = r[i-4] ^ r[i-8];
                r[i-5] = r[i-5] ^ r[i-8];
                r[i-6] = r[i-6] ^ r[i-8];
            }
            r[INIT_IDX + t]
        }
    }
    
    /// step mapping: $\iota(A) \rightarrow A^'$
    fn iota(&mut self, round_idx: i64) {
        let (w, l) = (self.w, self.l);
        let state = KeccakBufGuard::new(self);
        
        let mut rc = [0u8; KECCAK_Z_SIZE];
        for j in 0..=l {
            rc[(1<<j)-1] = Self::rc((j as i64) + 7 * round_idx);
        }
        
        for z in 0..w {
            state.input[(0,0,z)] = state.input[(0,0,z)] ^ rc[z];
        }
        std::mem::drop(state);
        let state = KeccakBufGuard::new(self);
        std::mem::drop(state);
    }
    
    /// the round function of the KECCAK-p[b,nr]
    fn rnd(&mut self, round_idx: i64) {
        self.theta();
        self.rho();
        self.pi();
        self.chi();
        self.iota(round_idx);
    }
    
    /// the permutation widths
    pub fn widths(&self) -> usize {
        self.b
    }
    
    fn init_state_arr(&mut self, byte_data: &[u8]) {
        // self.buf0.cvt_from_slice(byte_data, self.w);
        // self.state_flag = false;
        let w = self.w;
        let state = KeccakBufGuard::new(self);
        state.output.cvt_from_slice(byte_data, w);
    }
    
    fn permutation_inner(&mut self) {
        let (l, nr) = (self.l as i64, self.nr as i64);
        for round_idx in (12 + 2 * l - nr)..=(12 + 2 * l - 1) {
            self.rnd(round_idx);
        }
    }

    /// perform the KECCAK-p[b,nr] permutation, the `byte_data.len()` must be greater than or 
    /// equal to `(self.widths() + 7) / 8`. The extra bits will be discarded when the `byte_data.len()`
    /// greater than the `(self.widths() + 7) / 8`, the bits processed from left to right in writing order 
    /// and return the bit lengths of the `results` if success.;
    pub fn permutation(&mut self, byte_data: &[u8], results: &mut Vec<u8>) -> std::result::Result<usize, CryptoError> {
        let len = (self.widths() + 7) >> 3;
        if byte_data.len() < len {
            Err(CryptoError::new(InvalidParameter, 
                format!("Wrong bytes len: {}, the byte len must be great than or equal to the {}", byte_data.len(), len)))
        } else {
            self.init_state_arr(byte_data);
            
            self.permutation_inner();
            
            let (w, b) = (self.w, self.widths());
            let state = KeccakBufGuard::new(self);
            results.clear();
            state.input.finish(results, w);
            KeccakStateArr::cvt_to_slice(results);
            Ok(b)
        }
    }
    
    /// Sponge[Keccak-p[b,nr], pad10*1, rate]  
    /// `rate` must be a positive integer and strictly less than the width `self.widths()`.
    pub fn sponge(&self, rate: usize) -> std::result::Result<KeccakSponge, CryptoError> {
        KeccakSponge::new(self.clone(), rate)
    }
}


#[derive(Clone)]
pub struct KeccakSponge {
    rate: usize,
    keccak: Keccak,
    buf: Vec<u8>,
}

impl KeccakSponge {
    /// Sponge[Keccak-p[b,nr], pad10*1, rate]  
    /// `rate` must be a positive integer and strictly less than the width `self.widths()`.
    pub fn new(keccak: Keccak, rate: usize) -> Result<KeccakSponge, CryptoError> {
        if rate > 0 || rate < keccak.widths() {
            Ok(KeccakSponge {
                rate,
                keccak,
                buf: Vec::with_capacity(rate),
            })
        } else {
            Err(CryptoError::new(CryptoErrorKind::InvalidParameter,
                                 format!("Wrong rate: {}, keccak.widths: {}, the rate must satisfy the relations: 0 < rate < keccak.widths()", rate, keccak.widths())))
        }
    }

    /// 1 || 0^j || 1   
    /// return j
    #[inline]
    fn pad(x: usize, m: usize) -> usize {
        Keccak::minus_rem_euclid(0, m + 2, x)
    }
    
    pub(crate) fn clear_buf(&mut self) {
        self.buf.clear();
    }

    /// b0b1b2b3b4b5b6b7   
    /// hex = b7*2^7 + b6*2^6 + ... + b0*2^0   
    pub(crate) fn write_to_buf(&mut self, byte_data: &[u8], bits_len: usize) {
        let old_len = self.buf.len();
        byte_data.iter().for_each(|&e| {
            (0..8).for_each(|i| {
                self.buf.push((e >> i) & 1);
            });
        });
        if (self.buf.len()-old_len) > bits_len {self.buf.truncate(old_len + bits_len);}
    }
    
    /// `clear_buf`   
    /// `write_bot_buf()` many times  
    /// `sponge_buf`
    pub(crate) fn sponge_buf(&mut self, want_bits_len: usize, results: &mut Vec<u8>) {
        // byte_data || 1 || 0^j || 1
        let bits_len = self.buf.len();
        let pad_j = Self::pad(self.rate, bits_len);
        self.buf.push(1);
        self.buf.resize(bits_len + 1 + pad_j, 0);
        self.buf.push(1);

        let n = self.buf.len() / self.rate;
        // let c =  self.keccak.widths() - self.rate;

        {
            let state = KeccakBufGuard::new(&mut self.keccak);
            state.output.reset();
        }

        let (buf, rate, w) = (&mut self.buf, self.rate, self.keccak.w);
        for i in 0..n {
            {
                let state = KeccakBufGuard::new(&mut self.keccak);
                let start = i * self.rate;
                state.output.state.iter_mut().zip(state.input.state.iter()).enumerate().for_each(|(x, (sheeto, sheeti))| {
                    sheeto.iter_mut().zip(sheeti.iter()).enumerate().for_each(|(y, (laneo, lanei))| {
                        laneo.iter_mut().take(w).zip(lanei.iter().take(w)).enumerate().for_each(|(z, (eo, &ei))| {
                            let idx = (w * ((KECCAK_Y_SIZE * y) + x)) + z;
                            if idx >= rate {
                                *eo = ei ^ 0;
                            } else {
                                *eo = ei ^ buf[start + idx];
                            }
                        });
                    });
                });
            }

            self.keccak.permutation_inner();
        }

        results.clear();
        loop {
            let old_len = results.len();
            {
                let state = KeccakBufGuard::new(&mut self.keccak);
                state.input.finish(results, w);
            }

            // Z = Z || Trunc_r(S)
            results.truncate(old_len+self.rate);

            if want_bits_len <= results.len() {
                results.truncate(want_bits_len);
                break;
            } else {
                let state = KeccakBufGuard::new(&mut self.keccak);
                std::mem::drop(state);
                self.keccak.permutation_inner();
            }
        }

        KeccakStateArr::cvt_to_slice(results);
    }

    /// sponge the `byte_data` from the `bits_len` to the `want_bits_len`, and output the data to the results.  
    /// the bits processed from left to right in the writing order
    /// 
    /// # Panics
    /// 
    /// This function panics if `bits_len` greater than the `byte_data.len() * 8`
    pub fn sponge(&mut self, byte_data: &[u8], bits_len: usize, want_bits_len: usize, results: &mut Vec<u8>) {
        assert!(bits_len <= (byte_data.len() << 3), "bits_len must be less than or equal to the byte_data.len() * 8");
        
        self.clear_buf();
        self.write_to_buf(byte_data, bits_len);
        
        self.sponge_buf(want_bits_len, results);
    }
}

#[cfg(test)]
mod tests {
    use crate::keccak::keccak::KECCAK_PERMUTATION_WIDTHS;
    use crate::Keccak;

    #[test]
    fn keccak() {
        for &b in KECCAK_PERMUTATION_WIDTHS.iter() {
            let mut keccak = Keccak::new(b, 10).unwrap();
            let (mut s, mut sp) = (Vec::new(), Vec::new());
            s.resize((keccak.widths() + 7) >> 3, 0);
            keccak.permutation(s.as_slice(), &mut sp).unwrap();
            let mut sponge = keccak.sponge(b / 2).unwrap();
            sponge.sponge(s.as_slice(), 0, 1024, &mut sp);
            assert_eq!(1024/8, sp.len());
        }
    }
}