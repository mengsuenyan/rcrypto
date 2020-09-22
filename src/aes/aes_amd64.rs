//! AES have the two equivalent encrypt/decrypt step because the some reversibility of algebra operations.  
//! aes_generic.rs implemented by the standard step;  
//! aes_amd64 implemented by the another equivalent step due to the Intel AES instructions taking this method.
//! 
//! FIPS-197
//! 
//! https://www.cnblogs.com/mengsuenyan/p/12697694.html

#[cfg(target_arch = "x86")]
use core::arch::x86 as march;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as march;
use std::intrinsics::transmute;
use crate::aes::aes::AES_BLOCK_SIZE;

#[derive(Clone)]
pub struct AES {
    // big endian
    pub(super) enc_ks: Vec<march::__m128i>,
    pub(super) dec_ks: Vec<march::__m128i>,
    pub(super) nr: usize,
}

impl AES {
    #[target_feature(enable = "aes")]
    unsafe fn gen_dec_key(enc: &Vec<march::__m128i>, nr: usize, dec: &mut Vec<march::__m128i>) {
        dec.clear();
        dec.push(enc.last().unwrap().clone());
        enc.iter().rev().skip(1).take(nr - 1).for_each(|&e| {
            dec.push(march::_mm_aesimc_si128(e));
        });
        dec.push(enc.first().unwrap().clone());
    }
    
    #[target_feature(enable = "sse2")]
    unsafe fn aes_128_assist(temp1: march::__m128i, temp2: march::__m128i) -> march::__m128i {
        let temp2 = march::_mm_shuffle_epi32 (temp2 ,0xff);
        let temp3 = march::_mm_slli_si128 (temp1, 0x4);
        let temp1 = march::_mm_xor_si128 (temp1, temp3);
        let temp3 = march::_mm_slli_si128 (temp3, 0x4);
        let temp1 = march::_mm_xor_si128 (temp1, temp3);
        let temp3 = march::_mm_slli_si128 (temp3, 0x4);
        let temp1 = march::_mm_xor_si128 (temp1, temp3);
        march::_mm_xor_si128 (temp1, temp2)
    }
    
    #[target_feature(enable = "aes", enable = "sse2")]
    unsafe fn key_schedule_128(key: &[u8], enc: &mut Vec<march::__m128i>) {
        enc.clear();
        
        let key = transmute(key.as_ptr());
        let temp1 = march::_mm_loadu_si128(key);
        enc.push(temp1);
        let temp2 = march::_mm_aeskeygenassist_si128 (temp1 ,0x1);
        let temp1 = Self::aes_128_assist(temp1, temp2);
        enc.push(temp1);
        let temp2 = march::_mm_aeskeygenassist_si128 (temp1,0x2);
        let temp1 = Self::aes_128_assist(temp1, temp2);
        enc.push(temp1);
        let temp2 = march::_mm_aeskeygenassist_si128 (temp1,0x4);
        let temp1 = Self::aes_128_assist(temp1, temp2);
        enc.push(temp1);
        let temp2 = march::_mm_aeskeygenassist_si128 (temp1,0x8);
        let temp1 = Self::aes_128_assist(temp1, temp2);
        enc.push(temp1);
        let temp2 = march::_mm_aeskeygenassist_si128 (temp1,0x10);
        let temp1 = Self::aes_128_assist(temp1, temp2);
        enc.push(temp1);
        let temp2 = march::_mm_aeskeygenassist_si128 (temp1,0x20);
        let temp1 = Self::aes_128_assist(temp1, temp2);
        enc.push(temp1);
        let temp2 = march::_mm_aeskeygenassist_si128 (temp1,0x40);
        let temp1 = Self::aes_128_assist(temp1, temp2);
        enc.push(temp1);
        let temp2 = march::_mm_aeskeygenassist_si128 (temp1,0x80);
        let temp1 = Self::aes_128_assist(temp1, temp2);
        enc.push(temp1);
        let temp2 = march::_mm_aeskeygenassist_si128 (temp1,0x1b);
        let temp1 = Self::aes_128_assist(temp1, temp2);
        enc.push(temp1);
        let temp2 = march::_mm_aeskeygenassist_si128 (temp1,0x36);
        let temp1 = Self::aes_128_assist(temp1, temp2);
        enc.push(temp1);
    }

    #[target_feature(enable = "sse2")]
    unsafe fn key_192_assist(temp1: &mut march::__m128i, temp2: &mut march::__m128i, temp3: &mut march::__m128i) {
        *temp2 = march::_mm_shuffle_epi32 (*temp2, 0x55);
        let temp4 = march::_mm_slli_si128 (*temp1, 0x4);
        *temp1 = march::_mm_xor_si128 (*temp1, temp4);
        let temp4 = march::_mm_slli_si128 (temp4, 0x4);
        *temp1 = march::_mm_xor_si128 (*temp1, temp4);
        let temp4 = march::_mm_slli_si128 (temp4, 0x4);
        *temp1 = march::_mm_xor_si128 (*temp1, temp4);
        *temp1 = march::_mm_xor_si128 (*temp1, *temp2); 
        *temp2 = march::_mm_shuffle_epi32(*temp1, 0xff);
        let temp4 = march::_mm_slli_si128 (*temp3, 0x4);
        *temp3 = march::_mm_xor_si128 (*temp3, temp4);
        *temp3 = march::_mm_xor_si128 (*temp3, *temp2);
    }

    #[target_feature(enable = "sse2")]
    unsafe fn cvt_i2d(temp: *const march::__m128i) -> march::__m128d {
        march::_mm_load_pd(transmute(temp))
    }

    #[target_feature(enable = "sse2")]
    unsafe fn cvt_d2i(temp: *const march::__m128d) -> march::__m128i {
        march::_mm_loadu_si128(transmute(temp))
    }

    #[target_feature(enable = "aes", enable = "sse2")]
    unsafe fn key_schedule_192(key: &[u8], enc: &mut Vec<march::__m128i>) {
        let mut temp1 = march::_mm_loadu_si128(transmute(key.as_ptr()));
        let mut temp3= march::_mm_loadu_si128(transmute(key.as_ptr().offset(16)));
        enc.push(temp1);
        let key_temp= temp3;
        let mut temp2= march::_mm_aeskeygenassist_si128 (temp3,0x1);
        Self::key_192_assist(&mut temp1, &mut temp2, &mut temp3);
        let (x, y) = (Self::cvt_i2d(&key_temp), Self::cvt_i2d(&temp1));
        enc.push(Self::cvt_d2i(&march::_mm_shuffle_pd(x, y, 0)));
        enc.push(Self::cvt_d2i(&march::_mm_shuffle_pd(Self::cvt_i2d(&temp1), Self::cvt_i2d(&temp3), 1)));
        temp2 = march::_mm_aeskeygenassist_si128 (temp3,0x2);
        Self::key_192_assist(&mut temp1, &mut temp2, &mut temp3);
        enc.push(temp1);
        let key_temp = temp3;
        temp2=march::_mm_aeskeygenassist_si128 (temp3,0x4); 
        Self::key_192_assist(&mut temp1, &mut temp2, &mut temp3);
        enc.push(Self::cvt_d2i(&march::_mm_shuffle_pd(Self::cvt_i2d(&key_temp), Self::cvt_i2d(&temp1), 0)));
        enc.push(Self::cvt_d2i(&march::_mm_shuffle_pd(Self::cvt_i2d(&temp1), Self::cvt_i2d(&temp3), 1)));
        temp2=march::_mm_aeskeygenassist_si128 (temp3,0x8);
        Self::key_192_assist(&mut temp1, &mut temp2, &mut temp3);
        enc.push(temp1);
        let key_temp = temp3;
        temp2=march::_mm_aeskeygenassist_si128 (temp3,0x10);
        Self::key_192_assist(&mut temp1, &mut temp2, &mut temp3);
        enc.push(Self::cvt_d2i(&march::_mm_shuffle_pd(Self::cvt_i2d(&key_temp), Self::cvt_i2d(&temp1), 0)));
        enc.push(Self::cvt_d2i(&march::_mm_shuffle_pd(Self::cvt_i2d(&temp1), Self::cvt_i2d(&temp3), 1)));
        temp2=march::_mm_aeskeygenassist_si128 (temp3,0x20);    
        Self::key_192_assist(&mut temp1, &mut temp2, &mut temp3); 
        enc.push(temp1);
        let key_temp = temp3;
        temp2=march::_mm_aeskeygenassist_si128 (temp3,0x40);
        Self::key_192_assist(&mut temp1, &mut temp2, &mut temp3); 
        enc.push(Self::cvt_d2i(&march::_mm_shuffle_pd(Self::cvt_i2d(&key_temp), Self::cvt_i2d(&temp1), 0)));
        enc.push(Self::cvt_d2i(&march::_mm_shuffle_pd(Self::cvt_i2d(&temp1), Self::cvt_i2d(&temp3), 1)));
        temp2=march::_mm_aeskeygenassist_si128 (temp3,0x80);  
        Self::key_192_assist(&mut temp1, &mut temp2, &mut temp3);
        enc.push(temp1);
    }

    #[target_feature(enable = "sse2")]
    unsafe fn key_256_assist_1(temp1: &mut march::__m128i, temp2: &mut march::__m128i) {
        *temp2 = march::_mm_shuffle_epi32(*temp2, 0xff);
        let temp4 = march::_mm_slli_si128 (*temp1, 0x4);
        *temp1 = march::_mm_xor_si128 (*temp1, temp4); 
        let temp4 = march::_mm_slli_si128 (temp4, 0x4);
        *temp1 = march::_mm_xor_si128 (*temp1, temp4); 
        let temp4 = march::_mm_slli_si128 (temp4, 0x4);
        *temp1 = march::_mm_xor_si128 (*temp1, temp4);
        *temp1 = march::_mm_xor_si128 (*temp1, *temp2);
    }

    #[target_feature(enable = "sse2")]
    unsafe fn key_256_assist_2(temp1: &mut march::__m128i, temp3: &mut march::__m128i) {
        let temp4 = march::_mm_aeskeygenassist_si128 (*temp1, 0x0);
        let temp2 = march::_mm_shuffle_epi32(temp4, 0xaa);
        let temp4 = march::_mm_slli_si128 (*temp3, 0x4);
        *temp3 = march::_mm_xor_si128 (*temp3, temp4);
        let temp4 = march::_mm_slli_si128 (temp4, 0x4);
        *temp3 = march::_mm_xor_si128 (*temp3, temp4);
        let temp4 = march::_mm_slli_si128 (temp4, 0x4);
        *temp3 = march::_mm_xor_si128 (*temp3, temp4); 
        *temp3 = march::_mm_xor_si128 (*temp3, temp2);
    }


    #[target_feature(enable = "aes", enable = "sse2")]
    unsafe fn key_schedule_256(key: &[u8], enc: &mut Vec<march::__m128i>) {
        let mut temp1 = march::_mm_loadu_si128(transmute(key.as_ptr()));
        let mut temp3 = march::_mm_loadu_si128(transmute(key.as_ptr().offset(16)));
        enc.push(temp1);
        enc.push(temp3);
        let mut temp2 = march::_mm_aeskeygenassist_si128 (temp3,0x01);
        Self::key_256_assist_1(&mut temp1, &mut temp2);
        enc.push(temp1);
        Self::key_256_assist_2(&mut temp1, &mut temp3);
        enc.push(temp3);
        temp2 = march::_mm_aeskeygenassist_si128 (temp3,0x02); 
        Self::key_256_assist_1(&mut temp1, &mut temp2);
        enc.push(temp1);
        Self::key_256_assist_2(&mut temp1, &mut temp3);
        enc.push(temp3);
        temp2 = march::_mm_aeskeygenassist_si128 (temp3,0x04); 
        Self::key_256_assist_1(&mut temp1, &mut temp2); 
        enc.push(temp1); 
        Self::key_256_assist_2(&mut temp1, &mut temp3);
        enc.push(temp3); 
        temp2 = march::_mm_aeskeygenassist_si128 (temp3,0x08);
        Self::key_256_assist_1(&mut temp1, &mut temp2);
        enc.push(temp1); 
        Self::key_256_assist_2(&mut temp1, &mut temp3); 
        enc.push(temp3);  
        temp2 = march::_mm_aeskeygenassist_si128 (temp3,0x10); 
        Self::key_256_assist_1(&mut temp1, &mut temp2); 
        enc.push(temp1);  
        Self::key_256_assist_2(&mut temp1, &mut temp3);
        enc.push(temp3);  
        temp2 = march::_mm_aeskeygenassist_si128 (temp3,0x20); 
        Self::key_256_assist_1(&mut temp1, &mut temp2);  
        enc.push(temp1);  
        Self::key_256_assist_2(&mut temp1, &mut temp3); 
        enc.push(temp3);  
        temp2 = march::_mm_aeskeygenassist_si128 (temp3,0x40);
        Self::key_256_assist_1(&mut temp1, &mut temp2); 
        enc.push(temp1);
    }

    #[target_feature(enable = "aes", enable = "sse2")]
    unsafe fn crypt_block_inner(&self, dst: &mut Vec<u8>, pb: &[u8]) {
        let tmp = march::_mm_loadu_si128(transmute(pb.as_ptr()));
        let mut tmp = march::_mm_xor_si128(tmp, self.enc_ks[0]);
        self.enc_ks.iter().skip(1).take(self.nr - 1).for_each(|&e| {
            tmp = march::_mm_aesenc_si128(tmp, e);
        });
        tmp = march::_mm_aesenclast_si128(tmp, *self.enc_ks.last().unwrap());
        let mut buf = [0u8; AES_BLOCK_SIZE];
        march::_mm_storeu_si128(transmute(buf.as_mut_ptr()), tmp);
        dst.extend(buf.iter());
    }
    
    pub(super) fn crypt_block(&self, dst: &mut Vec<u8>, pb: &[u8]) {
        unsafe {
            self.crypt_block_inner(dst, pb);
        }
    }

    #[target_feature(enable = "aes", enable = "sse2")]
    unsafe fn decrypt_block_inner(&self, dst: &mut Vec<u8>, cipher: &[u8]) {
        let tmp = march::_mm_loadu_si128(transmute(cipher.as_ptr()));
        let mut tmp = march::_mm_xor_si128(tmp, self.dec_ks.first().unwrap().clone());
        self.dec_ks.iter().skip(1).take(self.nr - 1).for_each(|&e| {
            tmp = march::_mm_aesdec_si128(tmp, e);
        });
        tmp = march::_mm_aesdeclast_si128(tmp, self.dec_ks.last().unwrap().clone());
        let mut buf = [0u8; AES_BLOCK_SIZE];
        march::_mm_storeu_si128(transmute(buf.as_mut_ptr()), tmp);
        dst.extend(buf.iter());
    }
    
    pub(super) fn decrypt_block(&self, dst: &mut Vec<u8>, cipher: &[u8]) {
        unsafe {
            self.decrypt_block_inner(dst, cipher);
        }
    }

    pub fn aes_128(key: [u8; 16]) -> Self {
        let nr = 10;
        let (mut enc_ks, mut dec_ks) = (Vec::with_capacity(nr+1), Vec::with_capacity(nr+1));
        unsafe {
            Self::key_schedule_128(&key, &mut enc_ks);
            Self::gen_dec_key(&enc_ks, nr, &mut dec_ks);
        }
        
        AES {
            enc_ks,
            dec_ks,
            nr,
        }
    }

    pub fn aes_192(key: [u8; 24]) -> Self {
        let nr = 12;
        let (mut enc_ks, mut dec_ks) = (Vec::with_capacity(nr+1), Vec::with_capacity(nr+1));
        unsafe {
            Self::key_schedule_192(&key, &mut enc_ks);
            Self::gen_dec_key(&enc_ks, nr, &mut dec_ks);
        }

        AES {
            enc_ks,
            dec_ks,
            nr,
        }
    }

    pub fn aes_256(key: [u8; 32]) -> Self {
        let nr = 14;
        let (mut enc_ks, mut dec_ks) = (Vec::with_capacity(nr+1), Vec::with_capacity(nr+1));
        unsafe {
            Self::key_schedule_256(&key, &mut enc_ks);
            Self::gen_dec_key(&enc_ks, nr, &mut dec_ks);
        }

        AES {
            enc_ks,
            dec_ks,
            nr
        }
    }
}