use crate::sha::SHA1;

#[cfg(target_arch = "x86")]
use core::arch::x86 as march;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as march;
use std::intrinsics::transmute;

impl SHA1 {
    
    #[target_feature(enable = "sha")]
    unsafe fn update_amd64(digest: *mut u32, mut data: *const u8, num_blks: usize) {
        let e_mask    = march::_mm_set_epi64x(transmute(0xFFFFFFFF00000000u64), transmute(0x0000000000000000u64));
        let shuf_mask = march::_mm_set_epi64x(transmute(0x0001020304050607u64), transmute(0x08090a0b0c0d0e0fu64));

        // Load initial hash values
        let abcd = march::_mm_loadu_si128(transmute(digest));
        let e0 = march::_mm_set_epi32(transmute(digest.offset(4).read()), 0, 0, 0);
        let mut abcd      = march::_mm_shuffle_epi32(abcd, 0x1B);
        let mut e0        = march::_mm_and_si128(e0, e_mask);

       (0..num_blks).for_each(|_| {
            // Save hash values for addition after rounds
            let abcd_save = abcd;
            let e_save    = e0;

            // Rounds 0-3
            let msg0 = march::_mm_loadu_si128(transmute(data));
            let msg0 = march::_mm_shuffle_epi8(msg0, shuf_mask);
            e0   = march::_mm_add_epi32(e0, msg0);
            let e1   = abcd;
            abcd = march::_mm_sha1rnds4_epu32(abcd, e0, 0);

            // Rounds 4-7
            let msg1 = march::_mm_loadu_si128(transmute(data.offset(16)));
            let msg1 = march::_mm_shuffle_epi8(msg1, shuf_mask);
            let e1   = march::_mm_sha1nexte_epu32(e1, msg1);
            e0   = abcd;
            abcd = march::_mm_sha1rnds4_epu32(abcd, e1, 0);
            let msg0 = march::_mm_sha1msg1_epu32(msg0, msg1);

            // Rounds 8-11
            let msg2 = march::_mm_loadu_si128(transmute(data.offset(32)));
            let msg2 = march::_mm_shuffle_epi8(msg2, shuf_mask);
            e0   = march::_mm_sha1nexte_epu32(e0, msg2);
            let e1   = abcd;
            abcd = march::_mm_sha1rnds4_epu32(abcd, e0, 0);
            let msg1 = march::_mm_sha1msg1_epu32(msg1, msg2);
            let msg0 = march::_mm_xor_si128(msg0, msg2);

            // Rounds 12-15
            let msg3 = march::_mm_loadu_si128(transmute(data.offset(48)));
            let msg3 = march::_mm_shuffle_epi8(msg3, shuf_mask);
            let e1   = march::_mm_sha1nexte_epu32(e1, msg3);
            e0   = abcd;
            let msg0 = march::_mm_sha1msg2_epu32(msg0, msg3);
            abcd = march::_mm_sha1rnds4_epu32(abcd, e1, 0);
            let msg2 = march::_mm_sha1msg1_epu32(msg2, msg3);
            let msg1 = march::_mm_xor_si128(msg1, msg3);

            // Rounds 16-19
            let e0   = march::_mm_sha1nexte_epu32(e0, msg0);
            let e1   = abcd;
            let msg1 = march::_mm_sha1msg2_epu32(msg1, msg0);
            abcd = march::_mm_sha1rnds4_epu32(abcd, e0, 0);
            let msg3 = march::_mm_sha1msg1_epu32(msg3, msg0);
            let msg2 = march::_mm_xor_si128(msg2, msg0);

            // Rounds 20-23
            let e1   = march::_mm_sha1nexte_epu32(e1, msg1);
            let e0   = abcd;
            let msg2 = march::_mm_sha1msg2_epu32(msg2, msg1);
            abcd = march::_mm_sha1rnds4_epu32(abcd, e1, 1);
            let msg0 = march::_mm_sha1msg1_epu32(msg0, msg1);
            let msg3 = march::_mm_xor_si128(msg3, msg1);

            // Rounds 24-27
            let e0   = march::_mm_sha1nexte_epu32(e0, msg2);
            let e1   = abcd;
            let msg3 = march::_mm_sha1msg2_epu32(msg3, msg2);
            abcd = march::_mm_sha1rnds4_epu32(abcd, e0, 1);
            let msg1 = march::_mm_sha1msg1_epu32(msg1, msg2);
            let msg0 = march::_mm_xor_si128(msg0, msg2);

            // Rounds 28-31
            let e1   = march::_mm_sha1nexte_epu32(e1, msg3);
            let e0   = abcd;
            let msg0 = march::_mm_sha1msg2_epu32(msg0, msg3);
            abcd = march::_mm_sha1rnds4_epu32(abcd, e1, 1);
            let msg2 = march::_mm_sha1msg1_epu32(msg2, msg3);
            let msg1 = march::_mm_xor_si128(msg1, msg3);

            // Rounds 32-35
            let e0   = march::_mm_sha1nexte_epu32(e0, msg0);
            let e1   = abcd;
            let msg1 = march::_mm_sha1msg2_epu32(msg1, msg0);
            abcd = march::_mm_sha1rnds4_epu32(abcd, e0, 1);
            let msg3 = march::_mm_sha1msg1_epu32(msg3, msg0);
            let msg2 = march::_mm_xor_si128(msg2, msg0);

            // Rounds 36-39
            let e1   = march::_mm_sha1nexte_epu32(e1, msg1);
            let e0   = abcd;
            let msg2 = march::_mm_sha1msg2_epu32(msg2, msg1);
            abcd = march::_mm_sha1rnds4_epu32(abcd, e1, 1);
            let msg0 = march::_mm_sha1msg1_epu32(msg0, msg1);
            let msg3 = march::_mm_xor_si128(msg3, msg1);

            // Rounds 40-43
            let e0   = march::_mm_sha1nexte_epu32(e0, msg2);
            let e1   = abcd;
            let msg3 = march::_mm_sha1msg2_epu32(msg3, msg2);
            abcd = march::_mm_sha1rnds4_epu32(abcd, e0, 2);
            let msg1 = march::_mm_sha1msg1_epu32(msg1, msg2);
            let msg0 = march::_mm_xor_si128(msg0, msg2);

            // Rounds 44-47
            let e1   = march::_mm_sha1nexte_epu32(e1, msg3);
            let e0   = abcd;
            let msg0 = march::_mm_sha1msg2_epu32(msg0, msg3);
            abcd = march::_mm_sha1rnds4_epu32(abcd, e1, 2);
            let msg2 = march::_mm_sha1msg1_epu32(msg2, msg3);
            let msg1 = march::_mm_xor_si128(msg1, msg3);

            // Rounds 48-51
            let e0   = march::_mm_sha1nexte_epu32(e0, msg0);
            let e1   = abcd;
            let msg1 = march::_mm_sha1msg2_epu32(msg1, msg0);
            abcd = march::_mm_sha1rnds4_epu32(abcd, e0, 2);
            let msg3 = march::_mm_sha1msg1_epu32(msg3, msg0);
            let msg2 = march::_mm_xor_si128(msg2, msg0);

            // Rounds 52-55
            let e1   = march::_mm_sha1nexte_epu32(e1, msg1);
            let e0   = abcd;
            let msg2 = march::_mm_sha1msg2_epu32(msg2, msg1);
            abcd = march::_mm_sha1rnds4_epu32(abcd, e1, 2);
            let msg0 = march::_mm_sha1msg1_epu32(msg0, msg1);
            let msg3 = march::_mm_xor_si128(msg3, msg1);

            // Rounds 56-59
            let e0   = march::_mm_sha1nexte_epu32(e0, msg2);
            let e1   = abcd;
            let msg3 = march::_mm_sha1msg2_epu32(msg3, msg2);
            abcd = march::_mm_sha1rnds4_epu32(abcd, e0, 2);
            let msg1 = march::_mm_sha1msg1_epu32(msg1, msg2);
            let msg0 = march::_mm_xor_si128(msg0, msg2);

            // Rounds 60-63
            let e1   = march::_mm_sha1nexte_epu32(e1, msg3);
            let e0   = abcd;
            let msg0 = march::_mm_sha1msg2_epu32(msg0, msg3);
            abcd = march::_mm_sha1rnds4_epu32(abcd, e1, 3);
            let msg2 = march::_mm_sha1msg1_epu32(msg2, msg3);
            let msg1 = march::_mm_xor_si128(msg1, msg3);

            // Rounds 64-67
            let e0   = march::_mm_sha1nexte_epu32(e0, msg0);
            let e1   = abcd;
            let msg1 = march::_mm_sha1msg2_epu32(msg1, msg0);
            abcd = march::_mm_sha1rnds4_epu32(abcd, e0, 3);
            let msg3 = march::_mm_sha1msg1_epu32(msg3, msg0);
            let msg2 = march::_mm_xor_si128(msg2, msg0);

            // Rounds 68-71
            let e1   = march::_mm_sha1nexte_epu32(e1, msg1);
            let e0   = abcd;
            let msg2 = march::_mm_sha1msg2_epu32(msg2, msg1);
            abcd = march::_mm_sha1rnds4_epu32(abcd, e1, 3);
            let msg3 = march::_mm_xor_si128(msg3, msg1);

            // Rounds 72-75
            let e0   = march::_mm_sha1nexte_epu32(e0, msg2);
            let e1   = abcd;
            let msg3 = march::_mm_sha1msg2_epu32(msg3, msg2);
            abcd = march::_mm_sha1rnds4_epu32(abcd, e0, 3);

            // Rounds 76-79
            let e1   = march::_mm_sha1nexte_epu32(e1, msg3);
            let e0   = abcd;
            abcd = march::_mm_sha1rnds4_epu32(abcd, e1, 3);

            // Add current hash values with previously saved
            let e0   = march::_mm_sha1nexte_epu32(e0, e_save);
            abcd = march::_mm_add_epi32(abcd, abcd_save);
            data = data.offset(64);
        });

        abcd = march::_mm_shuffle_epi32(abcd, 0x1B);
         march::_mm_store_si128(transmute(digest), abcd);
        digest.offset(4).write(transmute(march::_mm_extract_epi32(e0, 3)));
    }

    pub(super) fn update(&mut self, data_block: Option<&[u8]>) {
        let data_block = match data_block {
             Some(x) => x,
             None => self.buf.as_ref(),
        };
         
         unsafe {
              Self::update_amd64(self.digest.as_mut_ptr(), data_block.as_ptr(), data_block.len() >> 6);
         }
    }
}