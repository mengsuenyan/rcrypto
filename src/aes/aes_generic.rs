use crate::aes::const_tables as mct;
use crate::crypto_err::{CryptoError, CryptoErrorKind};

#[derive(Clone)]
pub struct AES {
    // big endian
    pub(super) enc_ks: Vec<u32>,
    pub(super) dec_ks: Vec<u32>,
    pub(super) nr: usize,
}

impl AES {
    fn nk_nb_nr(key: &[u8]) -> (usize, usize, usize) {
        match key.len() {
            16 => (4, 4, 10),
            24 => (6, 4, 12),
            32 => (8, 4, 14),
            _ => unreachable!(),
        }
    }

    #[inline]
    fn sub_word(w: u32) -> u32 {
        let i = w.to_be_bytes();
        u32::from_be_bytes([mct::AES_SBOX0[i[0] as usize], mct::AES_SBOX0[i[1] as usize],
            mct::AES_SBOX0[i[2] as usize], mct::AES_SBOX0[i[3] as usize]])
    }

    /// Roundkey
    pub(super) fn key_schedule(key: &[u8], enc: &mut Vec<u32>, dec: &mut Vec<u32>) {
        enc.clear();
        dec.clear();

        let (nk, _, nr) = Self::nk_nb_nr(key);
        let mut v = [0u8;4];
        key.iter().enumerate().for_each(|(i, &k)| {
            v[i & 3] = k;
            if (i & 3) == 3 {
                enc.push(u32::from_be_bytes(v));
            }
        });

        let n = (nr + 1) << 2;
        enc.resize(n, 0);
        (nk..n).for_each(|i| {
            let tmp = enc[i - 1];
            let t = if (i % nk) == 0 {
                Self::sub_word(tmp.rotate_left(8)) ^ mct::AES_POWX[(i / nk) - 1]
            } else if (nk > 6) && ((i % nk) == 4) {
                Self::sub_word(tmp)
            } else {
                tmp
            };
            enc[i] = enc[i - nk] ^ t;
        });

        dec.resize(n, 0);
        let mut i = 0;
        while i < n {
            let ei = n - i - 4;
            for j in 0..4 {
                let mut x = enc[ei + j];
                if i > 0 && (i + 4) < n {
                    let v = x.to_be_bytes();
                    let (v0, v1, v2, v3) = (v[0] as usize, v[1] as usize, v[2] as usize, v[3] as usize);
                    x = mct::AES_TD0[mct::AES_SBOX0[v0] as usize] ^ mct::AES_TD1[mct::AES_SBOX0[v1] as usize] ^
                        mct::AES_TD2[mct::AES_SBOX0[v2] as usize] ^ mct::AES_TD3[mct::AES_SBOX0[v3] as usize];
                }
                dec[i+j] = x;
            }

            i += 4;
        }
    }

    pub(super) fn crypt_block(&self, dst: &mut Vec<u8>, pb: &[u8]) {
        let (mut s, mut itr) = ([0u32; 4], pb.iter());
        s.iter_mut().for_each(|a| {
            *a = u32::from_be_bytes([*itr.next().unwrap(), *itr.next().unwrap(), *itr.next().unwrap(),
                *itr.next().unwrap()]);
        });

        let key = &self.enc_ks;
        // AddRoundKey
        let (mut s0, mut s1, mut s2, mut s3) = (s[0] ^ key[0], s[1] ^ key[1], s[2] ^ key[2], s[3] ^ key[3]);

        // SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
        let mut k = 4;
        for _ in 0..(self.nr - 1) {
            let (v0, v1, v2, v3) = (s0.to_be_bytes(), s1.to_be_bytes(), s2.to_be_bytes(), s3.to_be_bytes());
            let t0  = key[k+0] ^ mct::AES_TE0[v0[0] as usize] ^ mct::AES_TE1[v1[1] as usize] ^ mct::AES_TE2[v2[2] as usize] ^ mct::AES_TE3[v3[3] as usize];
            let t1  = key[k+1] ^ mct::AES_TE0[v1[0] as usize] ^ mct::AES_TE1[v2[1] as usize] ^ mct::AES_TE2[v3[2] as usize] ^ mct::AES_TE3[v0[3] as usize];
            let t2  = key[k+2] ^ mct::AES_TE0[v2[0] as usize] ^ mct::AES_TE1[v3[1] as usize] ^ mct::AES_TE2[v0[2] as usize] ^ mct::AES_TE3[v1[3] as usize];
            let t3  = key[k+3] ^ mct::AES_TE0[v3[0] as usize] ^ mct::AES_TE1[v0[1] as usize] ^ mct::AES_TE2[v1[2] as usize] ^ mct::AES_TE3[v2[3] as usize];
            s0 = t0;
            s1 = t1;
            s2 = t2;
            s3 = t3;
            k += 4;
        }

        // SubBytes -> ShiftRows -> AddRoundKey
        let (v0, v1, v2, v3) = (s0.to_be_bytes(), s1.to_be_bytes(), s2.to_be_bytes(), s3.to_be_bytes());
        let tmp0 = [mct::AES_SBOX0[v0[0] as usize], mct::AES_SBOX0[v1[1] as usize], mct::AES_SBOX0[v2[2] as usize], mct::AES_SBOX0[v3[3] as usize]];
        let tmp1 = [mct::AES_SBOX0[v1[0] as usize], mct::AES_SBOX0[v2[1] as usize], mct::AES_SBOX0[v3[2] as usize], mct::AES_SBOX0[v0[3] as usize]];
        let tmp2 = [mct::AES_SBOX0[v2[0] as usize], mct::AES_SBOX0[v3[1] as usize], mct::AES_SBOX0[v0[2] as usize], mct::AES_SBOX0[v1[3] as usize]];
        let tmp3 = [mct::AES_SBOX0[v3[0] as usize], mct::AES_SBOX0[v0[1] as usize], mct::AES_SBOX0[v1[2] as usize], mct::AES_SBOX0[v2[3] as usize]];
        s0 = u32::from_be_bytes(tmp0);
        s1 = u32::from_be_bytes(tmp1);
        s2 = u32::from_be_bytes(tmp2);
        s3 = u32::from_be_bytes(tmp3);
        s0 ^= key[k+0];
        s1 ^= key[k+1];
        s2 ^= key[k+2];
        s3 ^= key[k+3];

        dst.extend(&s0.to_be_bytes());
        dst.extend(&s1.to_be_bytes());
        dst.extend(&s2.to_be_bytes());
        dst.extend(&s3.to_be_bytes());
    }

    pub(super) fn decrypt_block(&self, dst: &mut Vec<u8>, cipher: &[u8]) {
        let (mut s, mut itr) = ([0u32; 4], cipher.iter());
        s.iter_mut().for_each(|a| {
            *a = u32::from_be_bytes([*itr.next().unwrap(), *itr.next().unwrap(), *itr.next().unwrap(),
                *itr.next().unwrap()]);
        });
        
        let key = &self.dec_ks;
        // AddRoundKey
        let (mut s0, mut s1, mut s2, mut s3) = (s[0] ^ key[0], s[1] ^ key[1], s[2] ^ key[2], s[3] ^ key[3]);

        // SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
        let mut k = 4;
        for _ in 0..(self.nr - 1) {
            let (v0, v1, v2, v3) = (s0.to_be_bytes(), s1.to_be_bytes(), s2.to_be_bytes(), s3.to_be_bytes());
            let t0  = key[k+0] ^ mct::AES_TD0[v0[0] as usize] ^ mct::AES_TD1[v3[1] as usize] ^ mct::AES_TD2[v2[2] as usize] ^ mct::AES_TD3[v1[3] as usize];
            let t1  = key[k+1] ^ mct::AES_TD0[v1[0] as usize] ^ mct::AES_TD1[v0[1] as usize] ^ mct::AES_TD2[v3[2] as usize] ^ mct::AES_TD3[v2[3] as usize];
            let t2  = key[k+2] ^ mct::AES_TD0[v2[0] as usize] ^ mct::AES_TD1[v1[1] as usize] ^ mct::AES_TD2[v0[2] as usize] ^ mct::AES_TD3[v3[3] as usize];
            let t3  = key[k+3] ^ mct::AES_TD0[v3[0] as usize] ^ mct::AES_TD1[v2[1] as usize] ^ mct::AES_TD2[v1[2] as usize] ^ mct::AES_TD3[v0[3] as usize];
            s0 = t0;
            s1 = t1;
            s2 = t2;
            s3 = t3;
            k += 4;
        }

        // SubBytes -> ShiftRows -> AddRoundKey
        let (v0, v1, v2, v3) = (s0.to_be_bytes(), s1.to_be_bytes(), s2.to_be_bytes(), s3.to_be_bytes());
        let tmp0 = [mct::AES_SBOX1[v0[0] as usize], mct::AES_SBOX1[v3[1] as usize], mct::AES_SBOX1[v2[2] as usize], mct::AES_SBOX1[v1[3] as usize]];
        let tmp1 = [mct::AES_SBOX1[v1[0] as usize], mct::AES_SBOX1[v0[1] as usize], mct::AES_SBOX1[v3[2] as usize], mct::AES_SBOX1[v2[3] as usize]];
        let tmp2 = [mct::AES_SBOX1[v2[0] as usize], mct::AES_SBOX1[v1[1] as usize], mct::AES_SBOX1[v0[2] as usize], mct::AES_SBOX1[v3[3] as usize]];
        let tmp3 = [mct::AES_SBOX1[v3[0] as usize], mct::AES_SBOX1[v2[1] as usize], mct::AES_SBOX1[v1[2] as usize], mct::AES_SBOX1[v0[3] as usize]];
        s0 = u32::from_be_bytes(tmp0);
        s1 = u32::from_be_bytes(tmp1);
        s2 = u32::from_be_bytes(tmp2);
        s3 = u32::from_be_bytes(tmp3);
        s0 ^= key[k+0];
        s1 ^= key[k+1];
        s2 ^= key[k+2];
        s3 ^= key[k+3];
        
        dst.extend(&s0.to_be_bytes());
        dst.extend(&s1.to_be_bytes());
        dst.extend(&s2.to_be_bytes());
        dst.extend(&s3.to_be_bytes());
    }
}

macro_rules! aes_type_impl {
    ($Len: literal, $Key: ident, $NR: literal) => {
        let (mut enc_ks, mut dec_ks) = (Vec::with_capacity($Len), Vec::with_capacity($Len));
        Self::key_schedule(&$Key, &mut enc_ks, &mut dec_ks);
        
        return Self {
            enc_ks,
            dec_ks,
            nr: $NR,
        }
    };
}

impl AES {
    pub fn aes_128(key: [u8; 16]) -> Self {
        aes_type_impl!(44, key, 10);
    }

    pub fn aes_192(key: [u8; 24]) -> Self {
        aes_type_impl!(52, key, 12);
    }

    pub fn aes_256(key: [u8; 32]) -> Self {
        aes_type_impl!(60, key, 14);
    }
}