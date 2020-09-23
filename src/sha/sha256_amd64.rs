use crate::sha::SHA256;

#[cfg(target_arch = "x86")]
use core::arch::x86 as march;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as march;
use std::intrinsics::transmute;

impl SHA256 {

    #[target_feature(enable = "sha")]
    unsafe fn sha256_update_amd64(digest: *mut u32, mut data: *const u8, num_blks: usize) {
        // Load initial hash values
        // Need to reorder these appropriately
        // DCBA, HGFE -> ABEF, CDGH
        let tmp    = march::_mm_loadu_si128(transmute(digest));
        let state1 = march::_mm_loadu_si128(transmute(digest.offset(4)));

        let tmp    = march::_mm_shuffle_epi32(tmp, 0xB1);       // CDAB
        let state1 = march::_mm_shuffle_epi32(state1, 0x1B);    // EFGH
        let mut state0 = march::_mm_alignr_epi8(tmp, state1, 8);    // ABEF
        let mut state1 = march::_mm_blend_epi16(state1, tmp, 0xF0); // CDGH

        let shuf_mask = march::_mm_set_epi64x(transmute(0x0c0d0e0f08090a0bu64), transmute(0x0405060700010203u64));

        (0..num_blks).for_each(|_| {
            // Save hash values for addition after rounds
            abef_save = state0;
            cdgh_save = state1;

            // Rounds 0-3
            let msg     = march::_mm_loadu_si128(transmute( data));
            let msgtmp0 = march::_mm_shuffle_epi8(msg, shuf_mask);
            let msg    = march::_mm_add_epi32(msgtmp0,
                                   march::_mm_set_epi64x(transmute(0xE9B5DBA5B5C0FBCFu64), transmute(0x71374491428A2F98u64)));
            state1 = march::_mm_sha256rnds2_epu32(state1, state0, msg);
            let msg    = march::_mm_shuffle_epi32(msg, 0x0E);
            state0 = march::_mm_sha256rnds2_epu32(state0, state1, msg);

            // Rounds 4-7
            let msgtmp1 = march::_mm_loadu_si128(transmute(data.offset(16)));
            let msgtmp1 = march::_mm_shuffle_epi8(msgtmp1, shuf_mask);
            let msg    = march::_mm_add_epi32(msgtmp1,
                                   march::_mm_set_epi64x(transmute(0xAB1C5ED5923F82A4u64), transmute(0x59F111F13956C25Bu64)));
            state1 = march::_mm_sha256rnds2_epu32(state1, state0, msg);
            let msg    = march::_mm_shuffle_epi32(msg, 0x0E);
            state0 = march::_mm_sha256rnds2_epu32(state0, state1, msg);
            let msgtmp0 = march::_mm_sha256msg1_epu32(msgtmp0, msgtmp1);

            // Rounds 8-11
            let msgtmp2 = march::_mm_loadu_si128(transmute(data.offset(32)));
            let msgtmp2 = march::_mm_shuffle_epi8(msgtmp2, shuf_mask);
            let msg    = march::_mm_add_epi32(msgtmp2,
                                   march::_mm_set_epi64x(transmute(0x550C7DC3243185BEu64), transmute(0x12835B01D807AA98u64)));
            state1 = march::_mm_sha256rnds2_epu32(state1, state0, msg);
            let msg    = march::_mm_shuffle_epi32(msg, 0x0E);
            state0 = march::_mm_sha256rnds2_epu32(state0, state1, msg);
            let msgtmp1 = march::_mm_sha256msg1_epu32(msgtmp1, msgtmp2);

            // Rounds 12-15
            let msgtmp3 = march::_mm_loadu_si128(transmute(data.offset(48)));
            let msgtmp3 = march::_mm_shuffle_epi8(msgtmp3, shuf_mask);
            let msg    = march::_mm_add_epi32(msgtmp3,
                                   march::_mm_set_epi64x(transmute(0xC19BF1749BDC06A7u64), transmute(0x80DEB1FE72BE5D74u64)));
            state1 = march::_mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp     = march::_mm_alignr_epi8(msgtmp3, msgtmp2, 4);
            let msgtmp0 = march::_mm_add_epi32(msgtmp0, tmp);
            let msgtmp0 = march::_mm_sha256msg2_epu32(msgtmp0, msgtmp3);
            let msg    = march::_mm_shuffle_epi32(msg, 0x0E);
            state0 = march::_mm_sha256rnds2_epu32(state0, state1, msg);
            let msgtmp2 = march::_mm_sha256msg1_epu32(msgtmp2, msgtmp3);

            // Rounds 16-19
            let msg    = march::_mm_add_epi32(msgtmp0,
                                   march::_mm_set_epi64x(transmute(0x240CA1CC0FC19DC6u64), transmute(0xEFBE4786E49B69C1u64)));
            state1 = march::_mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp     = march::_mm_alignr_epi8(msgtmp0, msgtmp3, 4);
            let msgtmp1 = march::_mm_add_epi32(msgtmp1, tmp);
            let msgtmp1 = march::_mm_sha256msg2_epu32(msgtmp1, msgtmp0);
            let msg    = march::_mm_shuffle_epi32(msg, 0x0E);
            state0 = march::_mm_sha256rnds2_epu32(state0, state1, msg);
            let msgtmp3 = march::_mm_sha256msg1_epu32(msgtmp3, msgtmp0);

            // Rounds 20-23
            let msg    = march::_mm_add_epi32(msgtmp1,
                                   march::_mm_set_epi64x(transmute(0x76F988DA5CB0A9DCu64), transmute(0x4A7484AA2DE92C6Fu64)));
            state1 = march::_mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp     = march::_mm_alignr_epi8(msgtmp1, msgtmp0, 4);
            let msgtmp2 = march::_mm_add_epi32(msgtmp2, tmp);
            let msgtmp2 = march::_mm_sha256msg2_epu32(msgtmp2, msgtmp1);
            let msg    = march::_mm_shuffle_epi32(msg, 0x0E);
            state0 = march::_mm_sha256rnds2_epu32(state0, state1, msg);
            let msgtmp0 = march::_mm_sha256msg1_epu32(msgtmp0, msgtmp1);

            // Rounds 24-27
            let msg    = march::_mm_add_epi32(msgtmp2,
                                   march::_mm_set_epi64x(transmute(0xBF597FC7B00327C8u64), transmute(0xA831C66D983E5152u64)));
            state1 = march::_mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp     = march::_mm_alignr_epi8(msgtmp2, msgtmp1, 4);
            let msgtmp3 = march::_mm_add_epi32(msgtmp3, tmp);
            let msgtmp3 = march::_mm_sha256msg2_epu32(msgtmp3, msgtmp2);
            let msg    = march::_mm_shuffle_epi32(msg, 0x0E);
            state0 = march::_mm_sha256rnds2_epu32(state0, state1, msg);
            let msgtmp1 = march::_mm_sha256msg1_epu32(msgtmp1, msgtmp2);

            // Rounds 28-31
            let msg    = march::_mm_add_epi32(msgtmp3,
                                   march::_mm_set_epi64x(transmute(0x1429296706CA6351u64), transmute(0xD5A79147C6E00BF3u64)));
            state1 = march::_mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp     = march::_mm_alignr_epi8(msgtmp3, msgtmp2, 4);
            let msgtmp0 = march::_mm_add_epi32(msgtmp0, tmp);
            let msgtmp0 = march::_mm_sha256msg2_epu32(msgtmp0, msgtmp3);
            let msg    = march::_mm_shuffle_epi32(msg, 0x0E);
            state0 = march::_mm_sha256rnds2_epu32(state0, state1, msg);
            let msgtmp2 = march::_mm_sha256msg1_epu32(msgtmp2, msgtmp3);

            // Rounds 32-35
            let msg    = march::_mm_add_epi32(msgtmp0,
                                   march::_mm_set_epi64x(transmute(0x53380D134D2C6DFCu64), transmute(0x2E1B213827B70A85u64)));
            state1 = march::_mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp     = march::_mm_alignr_epi8(msgtmp0, msgtmp3, 4);
            let msgtmp1 = march::_mm_add_epi32(msgtmp1, tmp);
            let msgtmp1 = march::_mm_sha256msg2_epu32(msgtmp1, msgtmp0);
            let msg    = march::_mm_shuffle_epi32(msg, 0x0E);
            state0 = march::_mm_sha256rnds2_epu32(state0, state1, msg);
            let msgtmp3 = march::_mm_sha256msg1_epu32(msgtmp3, msgtmp0);

            // Rounds 36-39
            let msg    = march::_mm_add_epi32(msgtmp1,
                                   march::_mm_set_epi64x(transmute(0x92722C8581C2C92Eu64), transmute(0x766A0ABB650A7354u64)));
            state1 = march::_mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp     = march::_mm_alignr_epi8(msgtmp1, msgtmp0, 4);
            let msgtmp2 = march::_mm_add_epi32(msgtmp2, tmp);
            let msgtmp2 = march::_mm_sha256msg2_epu32(msgtmp2, msgtmp1);
            let msg    = march::_mm_shuffle_epi32(msg, 0x0E);
            state0 = march::_mm_sha256rnds2_epu32(state0, state1, msg);
            let msgtmp0 = march::_mm_sha256msg1_epu32(msgtmp0, msgtmp1);

            // Rounds 40-43
            let msg    = march::_mm_add_epi32(msgtmp2,
                                   march::_mm_set_epi64x(transmute(0xC76C51A3C24B8B70u64), transmute(0xA81A664BA2BFE8A1u64)));
            state1 = march::_mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp     = march::_mm_alignr_epi8(msgtmp2, msgtmp1, 4);
            let msgtmp3 = march::_mm_add_epi32(msgtmp3, tmp);
            let msgtmp3 = march::_mm_sha256msg2_epu32(msgtmp3, msgtmp2);
            let msg    = march::_mm_shuffle_epi32(msg, 0x0E);
            state0 = march::_mm_sha256rnds2_epu32(state0, state1, msg);
            let msgtmp1 = march::_mm_sha256msg1_epu32(msgtmp1, msgtmp2);

            // Rounds 44-47
            let msg    = march::_mm_add_epi32(msgtmp3,
                                   march::_mm_set_epi64x(transmute(0x106AA070F40E3585u64), transmute(0xD6990624D192E819u64)));
            state1 = march::_mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp     = march::_mm_alignr_epi8(msgtmp3, msgtmp2, 4);
            let msgtmp0 = march::_mm_add_epi32(msgtmp0, tmp);
            let msgtmp0 = march::_mm_sha256msg2_epu32(msgtmp0, msgtmp3);
            let msg    = march::_mm_shuffle_epi32(msg, 0x0E);
            state0 = march::_mm_sha256rnds2_epu32(state0, state1, msg);
            let msgtmp2 = march::_mm_sha256msg1_epu32(msgtmp2, msgtmp3);

            // Rounds 48-51
            let msg    = march::_mm_add_epi32(msgtmp0,
                                   march::_mm_set_epi64x(transmute(0x34B0BCB52748774Cu64), transmute(0x1E376C0819A4C116u64)));
            state1 = march::_mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp     = march::_mm_alignr_epi8(msgtmp0, msgtmp3, 4);
            let msgtmp1 = march::_mm_add_epi32(msgtmp1, tmp);
            let msgtmp1 = march::_mm_sha256msg2_epu32(msgtmp1, msgtmp0);
            let msg    = march::_mm_shuffle_epi32(msg, 0x0E);
            state0 = march::_mm_sha256rnds2_epu32(state0, state1, msg);
            let msgtmp3 = march::_mm_sha256msg1_epu32(msgtmp3, msgtmp0);

            // Rounds 52-55
            let msg    = march::_mm_add_epi32(msgtmp1,
                                   march::_mm_set_epi64x(transmute(0x682E6FF35B9CCA4Fu64), transmute(0x4ED8AA4A391C0CB3u64)));
            state1 = march::_mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp     = march::_mm_alignr_epi8(msgtmp1, msgtmp0, 4);
            let msgtmp2 = march::_mm_add_epi32(msgtmp2, tmp);
            let msgtmp2 = march::_mm_sha256msg2_epu32(msgtmp2, msgtmp1);
            let msg    = march::_mm_shuffle_epi32(msg, 0x0E);
            state0 = march::_mm_sha256rnds2_epu32(state0, state1, msg);

            let // Rounds 56-59
            msg    = march::_mm_add_epi32(msgtmp2,
                                   march::_mm_set_epi64x(transmute(0x8CC7020884C87814u64), transmute(0x78A5636F748F82EEu64)));
            state1 = march::_mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp     = march::_mm_alignr_epi8(msgtmp2, msgtmp1, 4);
            let msgtmp3 = march::_mm_add_epi32(msgtmp3, tmp);
            let msgtmp3 = march::_mm_sha256msg2_epu32(msgtmp3, msgtmp2);
            let msg    = march::_mm_shuffle_epi32(msg, 0x0E);
            state0 = march::_mm_sha256rnds2_epu32(state0, state1, msg);

            // Rounds 60-63
            let msg    = march::_mm_add_epi32(msgtmp3,
                                   march::_mm_set_epi64x(transmute(0xC67178F2BEF9A3F7u64), transmute(0xA4506CEB90BEFFFAu64)));
            state1 = march::_mm_sha256rnds2_epu32(state1, state0, msg);
            let msg    = march::_mm_shuffle_epi32(msg, 0x0E);
            state0 = march::_mm_sha256rnds2_epu32(state0, state1, msg);

            // Add current hash values with previously saved
            state0 = march::_mm_add_epi32(state0, abef_save);
            state1 = march::_mm_add_epi32(state1, cdgh_save);

            data = data.offset(64);
        });

        // Write hash values back in the correct order
        let tmp    = march::_mm_shuffle_epi32(state0, 0x1B);    // FEBA
        let state1 = march::_mm_shuffle_epi32(state1, 0xB1);    // DCHG
        let state0 = march::_mm_blend_epi16(tmp, state1, 0xF0); // DCBA
        let state1 = march::_mm_alignr_epi8(state1, tmp, 8);    // ABEF

        march::_mm_store_si128(transmute(digest), state0);
        march::_mm_store_si128(transmute(digest.offset(4)), state1);
    }

    pub(super) fn sha256_update(&mut self, data_block: Option<&[u8]>) {
        let mut data_block = match data_block {
            Some(x) => x,
            None => self.buf.as_ref(),
        };
        
        unsafe {
            Self::sha256_update_amd64(self.digest.as_mut_ptr(), data_block.as_ptr(), data_block.len() >> 6);
        }
    }
}