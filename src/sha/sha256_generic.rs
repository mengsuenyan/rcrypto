use crate::sha::SHA256;
use crate::sha::const_tables::{SHA256_BLOCK_SIZE, SHA256_WORD_LEN, f_ch, SHA256_K, f_maj};

impl SHA256 {
    #[inline]
    fn rotate_s0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline]
    fn rotate_s1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline]
    fn rotate_d0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline]
    fn rotate_d1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }


    pub(super) fn sha256_update(&mut self, data_block: Option<&[u8]>) {
        let data_block = match data_block {
            Some(x) => x,
            None => self.buf.as_ref(),
        };
        let mut chunk = 0;

        let digest = &mut self.digest;
        while chunk < data_block.len() {
            let block = &data_block[chunk..(chunk+SHA256_BLOCK_SIZE)];
            const LEN: usize = SHA256_BLOCK_SIZE / SHA256_WORD_LEN;
            let mut word = [0u32; 64];
            let mut itr = block.iter();
            for i in 0..LEN {
                let v = [*itr.next().unwrap(), *itr.next().unwrap(), *itr.next().unwrap(), *itr.next().unwrap()];
                word[i] = u32::from_be_bytes(v);
            }

            for j in LEN..64 {
                word[j] = Self::rotate_d1(word[j-2]).wrapping_add(word[j-7]).wrapping_add(Self::rotate_d0(word[j-15])).wrapping_add(word[j-16]);
            }

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]);
            for j in 0..64 {
                // if j > 15 {
                //     word[j] = Self::rotate_d1(word[j-2]).wrapping_add(word[j-7]).wrapping_add(Self::rotate_d0(word[j-15])).wrapping_add(word[j-16]);
                // }
                let t1 = h.wrapping_add(Self::rotate_s1(e)).wrapping_add(f_ch(e,f,g)).wrapping_add(SHA256_K[j]).wrapping_add(word[j]);
                let t2 = Self::rotate_s0(a).wrapping_add(f_maj(a,b,c));
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }

            digest[0] = a.wrapping_add(digest[0]);
            digest[1] = b.wrapping_add(digest[1]);
            digest[2] = c.wrapping_add(digest[2]);
            digest[3] = d.wrapping_add(digest[3]);
            digest[4] = e.wrapping_add(digest[4]);
            digest[5] = f.wrapping_add(digest[5]);
            digest[6] = g.wrapping_add(digest[6]);
            digest[7] = h.wrapping_add(digest[7]);
            chunk += SHA256_BLOCK_SIZE;
        }
    }
}