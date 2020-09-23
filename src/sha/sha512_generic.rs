use crate::sha::SHA512;
use crate::sha::const_tables::{SHA512_BLOCK_SIZE, f_ch, SHA512_K, f_maj};

impl SHA512 {
    #[inline]
    fn rotate_s0(x: u64) -> u64 {
        x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
    }

    #[inline]
    fn rotate_s1(x: u64) -> u64 {
        x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
    }

    #[inline]
    fn rotate_d0(x: u64) -> u64 {
        x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
    }

    #[inline]
    fn rotate_d1(x: u64) -> u64 {
        x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
    }

    pub(super) fn sha512_update(&mut self, data_block: Option<&[u8]>) {
        let data_block = match data_block {
            Some(x) => x,
            None => self.buf.as_ref(),
        };
        let mut chunk = 0;

        let digest = &mut self.digest;
        while chunk < data_block.len() {
            let bytes = &data_block[chunk..(chunk+SHA512_BLOCK_SIZE)];
            let mut word = [0u64; 80];
            let mut itr = bytes.iter();
            for i in 0..16 {
                let v = [*itr.next().unwrap(), *itr.next().unwrap(), *itr.next().unwrap(), *itr.next().unwrap(),
                    *itr.next().unwrap(), *itr.next().unwrap(), *itr.next().unwrap(), *itr.next().unwrap()];
                word[i] = u64::from_be_bytes(v);
            }

            for i in 16..80 {
                word[i] = Self::rotate_d1(word[i-2]).wrapping_add(word[i-7]).wrapping_add(Self::rotate_d0(word[i-15])).wrapping_add(word[i-16]);
            }

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (digest[0], digest[1], digest[2], digest[3], digest[4],
                                                                            digest[5], digest[6], digest[7]);

            for j in 0..80 {
                let t1 = h.wrapping_add(Self::rotate_s1(e)).wrapping_add(f_ch(e,f,g)).wrapping_add(SHA512_K[j]).wrapping_add(word[j]);
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
            chunk += SHA512_BLOCK_SIZE;
        }
    }
}