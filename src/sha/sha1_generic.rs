use crate::sha::const_tables::{SHA1_BLOCK_SIZE, SHA1_WORD_LEN, f_ch, SHA1_K, f_parity, f_maj};
use crate::sha::SHA1;

macro_rules! sha1_upd_digest {
    ($a: ident, $b: ident, $c: ident, $d: ident, $e: ident, $A: ident, $B: ident, $C: ident, $D: ident, $E: ident) => {
        {
            let (aa, bb, cc, dd, ee) = ($A, $B, $C, $D, $E);
            $a = aa;
            $b = bb;
            $c = cc;
            $d = dd;
            $e = ee;
        };
    };
}


impl SHA1 {

    #[inline]
    fn f_word_extract(w: &mut [u32; SHA1_BLOCK_SIZE/SHA1_WORD_LEN], s: usize) -> u32 {
        w[s&0xf] = (w[(s+13)&0xf] ^ w[(s+8)&0xf] ^ w[(s+2)&0xf] ^ w[s&0xf]).rotate_left(1);
        // w[s&0xf] = (w[(s-3)&0xf] ^ w[(s-8)&0xf] ^ w[(s-14)&0xf] ^ w[(s-16)&0xf]).rotate_left(1);
        w[s&0xf]
    }


    pub(super) fn update(&mut self, data_block: Option<&[u8]>) {
        let data_block = match data_block {
            Some(x) => x,
            None => self.buf.as_ref(),
        };

        let mut chunk = 0;

        while chunk < data_block.len() {
            let bytes = &data_block[chunk..(chunk+SHA1_BLOCK_SIZE)];

            const LEN: usize = SHA1_BLOCK_SIZE / SHA1_WORD_LEN;
            let mut word = [0u32; LEN];
            let mut bytes_itr = bytes.iter();
            for i in 0..LEN {
                let v = [*bytes_itr.next().unwrap(), *bytes_itr.next().unwrap(), *bytes_itr.next().unwrap(), *bytes_itr.next().unwrap()];
                word[i] = u32::from_be_bytes(v);
            }

            let (mut a, mut b, mut c, mut d, mut e) = (self.digest[0], self.digest[1], self.digest[2], self.digest[3], self.digest[4]);

            let mut j = 0;
            while j < 16 {
                let t = a.rotate_left(5).wrapping_add(f_ch(b, c, d)).wrapping_add(e).wrapping_add(SHA1_K[0]).wrapping_add(word[j]);
                let b_p = b.rotate_left(30);
                sha1_upd_digest!(a, b, c, d, e, t, a, b_p, c, d);
                j += 1;
            }

            while j < 20 {
                let t = a.rotate_left(5).wrapping_add(f_ch(b, c, d)).wrapping_add(e).wrapping_add(SHA1_K[0]).wrapping_add(SHA1::f_word_extract(&mut word, j));
                let b_p = b.rotate_left(30);
                sha1_upd_digest!(a, b, c, d, e, t, a, b_p, c, d);
                j += 1;
            }

            while j < 40 {
                let t = a.rotate_left(5).wrapping_add(f_parity(b, c, d)).wrapping_add(e).wrapping_add(SHA1_K[1]).wrapping_add(SHA1::f_word_extract(&mut word, j));
                let b_p = b.rotate_left(30);
                sha1_upd_digest!(a, b, c, d, e, t, a, b_p, c, d);
                j += 1;
            }

            while j < 60 {
                let t = a.rotate_left(5).wrapping_add(f_maj(b, c, d)).wrapping_add(e).wrapping_add(SHA1_K[2]).wrapping_add(SHA1::f_word_extract(&mut word, j));
                let b_p = b.rotate_left(30);
                sha1_upd_digest!(a, b, c, d, e, t, a, b_p, c, d);
                j += 1;
            }

            while j < 80 {
                let t = a.rotate_left(5).wrapping_add(f_parity(b, c, d)).wrapping_add(e).wrapping_add(SHA1_K[3]).wrapping_add(SHA1::f_word_extract(&mut word, j));
                let b_p = b.rotate_left(30);
                sha1_upd_digest!(a, b, c, d, e, t, a, b_p, c, d);
                j += 1;
            }

            self.digest[0] = a.wrapping_add(self.digest[0]);
            self.digest[1] = b.wrapping_add(self.digest[1]);
            self.digest[2] = c.wrapping_add(self.digest[2]);
            self.digest[3] = d.wrapping_add(self.digest[3]);
            self.digest[4] = e.wrapping_add(self.digest[4]);
            chunk += SHA1_BLOCK_SIZE;
        }
    }
}