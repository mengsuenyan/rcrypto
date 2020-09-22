use crate::MD5;
use crate::md5::md5::MD5_BLOCK_SIZE;

#[cfg(target_arch = "x86")]
use core::arch::x86 as march;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as march;
use std::intrinsics::transmute;

macro_rules! round1 {
    ($A: ident, $B: ident, $C: ident, $D: ident, $X: expr, $CON: expr, $SHI: literal) => {
        let temp1 = march::_mm_xor_si128(march::_mm_and_si128(march::_mm_xor_si128($C, $D), $B), $D);
        let temp3 = march::_mm_add_epi32(temp1, $A);
        let temp4 = march::_mm_add_epi32($X, temp3);
        let temp5 = march::_mm_add_epi32(march::_mm_set1_epi32($CON), temp4);
        let temp6 = march::_mm_slli_epi32(temp5, $SHI);
        let temp7 = march::_mm_srli_epi32(temp5, 32 - $SHI);
        let temp2 = march::_mm_or_si128(temp6, temp7);
        $A = march::_mm_add_epi32(temp2, $B);
    };
}

macro_rules! round2 {
    ($A: ident, $B: ident, $C: ident, $D: ident, $X: expr, $CON: expr, $SHI: literal) => {
        let temp1 = march::_mm_xor_si128(march::_mm_and_si128(march::_mm_xor_si128($B, $C), $D), $C);
        let temp3 = march::_mm_add_epi32(temp1, $A);
        let temp4 = march::_mm_add_epi32($X, temp3);
        let temp5 = march::_mm_add_epi32(march::_mm_set1_epi32($CON), temp4);
        let temp6 = march::_mm_slli_epi32(temp5, $SHI);
        let temp7 = march::_mm_srli_epi32(temp5, 32 - $SHI);
        let temp2 = march::_mm_or_si128(temp6, temp7);
        $A = march::_mm_add_epi32(temp2, $B);
    };
}

macro_rules! round3 {
    ($A: ident, $B: ident, $C: ident, $D: ident, $X: expr, $CON: expr, $SHI: literal) => {
        let temp1 = march::_mm_xor_si128(march::_mm_xor_si128($B, $C), $D);
        let temp3 = march::_mm_add_epi32(temp1, $A);
        let temp4 = march::_mm_add_epi32($X, temp3);
        let temp5 = march::_mm_add_epi32(march::_mm_set1_epi32($CON), temp4);
        let temp6 = march::_mm_slli_epi32(temp5, $SHI);
        let temp7 = march::_mm_srli_epi32(temp5, 32 - $SHI);
        let temp2 = march::_mm_or_si128(temp6, temp7);
        $A = march::_mm_add_epi32(temp2, $B);
    };
}

macro_rules! round4 {
    ($A: ident, $B: ident, $C: ident, $D: ident, $X: expr, $CON: expr, $SHI: literal) => {
        let temp1 = march::_mm_xor_si128($C, march::_mm_or_si128($B, march::_mm_xor_si128(march::_mm_set1_epi8(transmute(0xffu8)), $D)));
        let temp3 = march::_mm_add_epi32(temp1, $A);
        let temp4 = march::_mm_add_epi32($X, temp3);
        let temp5 = march::_mm_add_epi32(march::_mm_set1_epi32($CON), temp4);
        let temp6 = march::_mm_slli_epi32(temp5, $SHI);
        let temp7 = march::_mm_srli_epi32(temp5, 32 - $SHI);
        let temp2 = march::_mm_or_si128(temp6, temp7);
        $A = march::_mm_add_epi32(temp2, $B);
    };
}

impl MD5 {
    pub(super) fn update(&mut self, data_block: Option<&[u8]>) {
        unsafe {
            Self::update_inner(self, data_block);
        }
    }
    
    #[target_feature(enable = "sse2")]
    unsafe fn update_inner(&mut self, data_block: Option<&[u8]>) {
        let data_block = match data_block {
            Some(x) => x,
            None => &self.buf
        };
        
        let (mut a, mut b, mut c, mut d) = (
            march::_mm_set1_epi32(transmute(self.digest[0])),
            march::_mm_set1_epi32(transmute(self.digest[1])),
            march::_mm_set1_epi32(transmute(self.digest[2])),
            march::_mm_set1_epi32(transmute(self.digest[3])),
        );

        let mut i = 0;
        while i < data_block.len() {
            let (aa, bb, cc, dd) = (a, b, c, d);
            let mut x = [march::_mm_set1_epi32(0); 16];
            let msg = &data_block[i..(i+MD5_BLOCK_SIZE)];
            let mut msg_itr = msg.iter();
            for j in 0..16 {
                let v = [*msg_itr.next().unwrap(), *msg_itr.next().unwrap(), *msg_itr.next().unwrap(), *msg_itr.next().unwrap()];
                x[j] = march::_mm_set1_epi32(transmute(u32::from_le_bytes(v)));
            }


            round1!(a,b,c,d,x[0],transmute(0xd76aa478u32),7);
            round1!(d,a,b,c,x[1],transmute(0xe8c7b756u32),12);
            round1!(c,d,a,b,x[2],transmute(0x242070dbu32),17);
            round1!(b,c,d,a,x[3],transmute(0xc1bdceeeu32),22);
            round1!(a,b,c,d,x[4],transmute(0xf57c0fafu32),7);
            round1!(d,a,b,c,x[5],transmute(0x4787c62au32),12);
            round1!(c,d,a,b,x[6],transmute(0xa8304613u32),17);
            round1!(b,c,d,a,x[7],transmute(0xfd469501u32),22);
            round1!(a,b,c,d,x[8],transmute(0x698098d8u32),7);
            round1!(d,a,b,c,x[9],transmute(0x8b44f7afu32),12);
            round1!(c,d,a,b,x[10],transmute(0xffff5bb1u32),17);
            round1!(b,c,d,a,x[11],transmute(0x895cd7beu32),22);
            round1!(a,b,c,d,x[12],transmute(0x6b901122u32),7);
            round1!(d,a,b,c,x[13],transmute(0xfd987193u32),12);
            round1!(c,d,a,b,x[14],transmute(0xa679438eu32),17);
            round1!(b,c,d,a,x[15],transmute(0x49b40821u32),22);

            round2!(a,b,c,d,x[1],transmute(0xf61e2562u32),5);
            round2!(d,a,b,c,x[6],transmute(0xc040b340u32),9);
            round2!(c,d,a,b,x[11],transmute(0x265e5a51u32),14);
            round2!(b,c,d,a,x[0],transmute(0xe9b6c7aau32),20);
            round2!(a,b,c,d,x[5],transmute(0xd62f105du32),5);
            round2!(d,a,b,c,x[10],transmute(0x02441453u32),9);
            round2!(c,d,a,b,x[15],transmute(0xd8a1e681u32),14);
            round2!(b,c,d,a,x[4],transmute(0xe7d3fbc8u32),20);
            round2!(a,b,c,d,x[9],transmute(0x21e1cde6u32),5);
            round2!(d,a,b,c,x[14],transmute(0xc33707d6u32),9);
            round2!(c,d,a,b,x[3],transmute(0xf4d50d87u32),14);
            round2!(b,c,d,a,x[8],transmute(0x455a14edu32),20);
            round2!(a,b,c,d,x[13],transmute(0xa9e3e905u32),5);
            round2!(d,a,b,c,x[2],transmute(0xfcefa3f8u32),9);
            round2!(c,d,a,b,x[7],transmute(0x676f02d9u32),14);
            round2!(b,c,d,a,x[12],transmute(0x8d2a4c8au32),20);

            // round 3
            round3!(a,b,c,d,x[5],transmute(0xfffa3942u32),4);
            round3!(d,a,b,c,x[8],transmute(0x8771f681u32),11);
            round3!(c,d,a,b,x[11],transmute(0x6d9d6122u32),16);
            round3!(b,c,d,a,x[14],transmute(0xfde5380cu32),23);
            round3!(a,b,c,d,x[1],transmute(0xa4beea44u32),4);
            round3!(d,a,b,c,x[4],transmute(0x4bdecfa9u32),11);
            round3!(c,d,a,b,x[7],transmute(0xf6bb4b60u32),16);
            round3!(b,c,d,a,x[10],transmute(0xbebfbc70u32),23);
            round3!(a,b,c,d,x[13],transmute(0x289b7ec6u32),4);
            round3!(d,a,b,c,x[0],transmute(0xeaa127fau32),11);
            round3!(c,d,a,b,x[3],transmute(0xd4ef3085u32),16);
            round3!(b,c,d,a,x[6],transmute(0x04881d05u32),23);
            round3!(a,b,c,d,x[9],transmute(0xd9d4d039u32),4);
            round3!(d,a,b,c,x[12],transmute(0xe6db99e5u32),11);
            round3!(c,d,a,b,x[15],transmute(0x1fa27cf8u32),16);
            round3!(b,c,d,a,x[2],transmute(0xc4ac5665u32),23);

            // round 4
            round4!(a,b,c,d,x[0],transmute(0xf4292244u32),6);
            round4!(d,a,b,c,x[7],transmute(0x432aff97u32),10);
            round4!(c,d,a,b,x[14],transmute(0xab9423a7u32),15);
            round4!(b,c,d,a,x[5],transmute(0xfc93a039u32),21);
            round4!(a,b,c,d,x[12],transmute(0x655b59c3u32),6);
            round4!(d,a,b,c,x[3],transmute(0x8f0ccc92u32),10);
            round4!(c,d,a,b,x[10],transmute(0xffeff47du32),15);
            round4!(b,c,d,a,x[1],transmute(0x85845dd1u32),21);
            round4!(a,b,c,d,x[8],transmute(0x6fa87e4fu32),6);
            round4!(d,a,b,c,x[15],transmute(0xfe2ce6e0u32),10);
            round4!(c,d,a,b,x[6],transmute(0xa3014314u32),15);
            round4!(b,c,d,a,x[13],transmute(0x4e0811a1u32),21);
            round4!(a,b,c,d,x[4],transmute(0xf7537e82u32),6);
            round4!(d,a,b,c,x[11],transmute(0xbd3af235u32),10);
            round4!(c,d,a,b,x[2],transmute(0x2ad7d2bbu32),15);
            round4!(b,c,d,a,x[9],transmute(0xeb86d391u32),21);
            
            a = march::_mm_add_epi32(aa, a);
            b = march::_mm_add_epi32(bb, b);
            c = march::_mm_add_epi32(cc, c);
            d = march::_mm_add_epi32(dd, d);
            
            i += MD5_BLOCK_SIZE;
        }
        
        let buf = [0u32; 4];
        march::_mm_storeu_si128(transmute(buf.as_ptr()), a);
        self.digest[0] = buf[0];
        march::_mm_storeu_si128(transmute(buf.as_ptr()), b);
        self.digest[1] = buf[0];
        march::_mm_storeu_si128(transmute(buf.as_ptr()), c);
        self.digest[2] = buf[0];
        march::_mm_storeu_si128(transmute(buf.as_ptr()), d);
        self.digest[3] = buf[0];
    }
}