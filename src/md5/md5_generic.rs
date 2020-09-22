use crate::md5::MD5;
use crate::md5::md5::MD5_BLOCK_SIZE;

impl MD5 {
    pub(super) fn update(&mut self, data_block: Option<&[u8]>) {
        let data_block = match data_block {Some(x) => x, None => &self.buf};
        let (mut a, mut b, mut c, mut d) = (self.digest[0], self.digest[1], self.digest[2], self.digest[3]);

        let mut i = 0;
        while i < data_block.len() {
            let (aa, bb, cc, dd) = (a, b, c, d);
            let mut x = [0u32; 16];
            let msg = &data_block[i..(i+MD5_BLOCK_SIZE)];
            let mut msg_itr = msg.iter();
            for j in 0..16 {
                let v = [*msg_itr.next().unwrap(), *msg_itr.next().unwrap(), *msg_itr.next().unwrap(), *msg_itr.next().unwrap()];
                x[j] = u32::from_le_bytes(v);
            }

            // round 1
            a = b.wrapping_add((((c^d)&b)^d).wrapping_add(a).wrapping_add(x[0]).wrapping_add(0xd76aa478).rotate_left(7));
            d = a.wrapping_add((((b^c)&a)^c).wrapping_add(d).wrapping_add(x[1]).wrapping_add(0xe8c7b756).rotate_left(12));
            c = d.wrapping_add((((a^b)&d)^b).wrapping_add(c).wrapping_add(x[2]).wrapping_add(0x242070db).rotate_left(17));
            b = c.wrapping_add((((d^a)&c)^a).wrapping_add(b).wrapping_add(x[3]).wrapping_add(0xc1bdceee).rotate_left(22));
            a = b.wrapping_add((((c^d)&b)^d).wrapping_add(a).wrapping_add(x[4]).wrapping_add(0xf57c0faf).rotate_left(7));
            d = a.wrapping_add((((b^c)&a)^c).wrapping_add(d).wrapping_add(x[5]).wrapping_add(0x4787c62a).rotate_left(12));
            c = d.wrapping_add((((a^b)&d)^b).wrapping_add(c).wrapping_add(x[6]).wrapping_add(0xa8304613).rotate_left(17));
            b = c.wrapping_add((((d^a)&c)^a).wrapping_add(b).wrapping_add(x[7]).wrapping_add(0xfd469501).rotate_left(22));
            a = b.wrapping_add((((c^d)&b)^d).wrapping_add(a).wrapping_add(x[8]).wrapping_add(0x698098d8).rotate_left(7));
            d = a.wrapping_add((((b^c)&a)^c).wrapping_add(d).wrapping_add(x[9]).wrapping_add(0x8b44f7af).rotate_left(12));
            c = d.wrapping_add((((a^b)&d)^b).wrapping_add(c).wrapping_add(x[10]).wrapping_add(0xffff5bb1).rotate_left(17));
            b = c.wrapping_add((((d^a)&c)^a).wrapping_add(b).wrapping_add(x[11]).wrapping_add(0x895cd7be).rotate_left(22));
            a = b.wrapping_add((((c^d)&b)^d).wrapping_add(a).wrapping_add(x[12]).wrapping_add(0x6b901122).rotate_left(7));
            d = a.wrapping_add((((b^c)&a)^c).wrapping_add(d).wrapping_add(x[13]).wrapping_add(0xfd987193).rotate_left(12));
            c = d.wrapping_add((((a^b)&d)^b).wrapping_add(c).wrapping_add(x[14]).wrapping_add(0xa679438e).rotate_left(17));
            b = c.wrapping_add((((d^a)&c)^a).wrapping_add(b).wrapping_add(x[15]).wrapping_add(0x49b40821).rotate_left(22));

            // round 2
            a = b.wrapping_add((((b^c)&d)^c).wrapping_add(a).wrapping_add(x[1]).wrapping_add(0xf61e2562).rotate_left(5));
            d = a.wrapping_add((((a^b)&c)^b).wrapping_add(d).wrapping_add(x[6]).wrapping_add(0xc040b340).rotate_left(9));
            c = d.wrapping_add((((d^a)&b)^a).wrapping_add(c).wrapping_add(x[11]).wrapping_add(0x265e5a51).rotate_left(14));
            b = c.wrapping_add((((c^d)&a)^d).wrapping_add(b).wrapping_add(x[0]).wrapping_add(0xe9b6c7aa).rotate_left(20));
            a = b.wrapping_add((((b^c)&d)^c).wrapping_add(a).wrapping_add(x[5]).wrapping_add(0xd62f105d).rotate_left(5));
            d = a.wrapping_add((((a^b)&c)^b).wrapping_add(d).wrapping_add(x[10]).wrapping_add(0x02441453).rotate_left(9));
            c = d.wrapping_add((((d^a)&b)^a).wrapping_add(c).wrapping_add(x[15]).wrapping_add(0xd8a1e681).rotate_left(14));
            b = c.wrapping_add((((c^d)&a)^d).wrapping_add(b).wrapping_add(x[4]).wrapping_add(0xe7d3fbc8).rotate_left(20));
            a = b.wrapping_add((((b^c)&d)^c).wrapping_add(a).wrapping_add(x[9]).wrapping_add(0x21e1cde6).rotate_left(5));
            d = a.wrapping_add((((a^b)&c)^b).wrapping_add(d).wrapping_add(x[14]).wrapping_add(0xc33707d6).rotate_left(9));
            c = d.wrapping_add((((d^a)&b)^a).wrapping_add(c).wrapping_add(x[3]).wrapping_add(0xf4d50d87).rotate_left(14));
            b = c.wrapping_add((((c^d)&a)^d).wrapping_add(b).wrapping_add(x[8]).wrapping_add(0x455a14ed).rotate_left(20));
            a = b.wrapping_add((((b^c)&d)^c).wrapping_add(a).wrapping_add(x[13]).wrapping_add(0xa9e3e905).rotate_left(5));
            d = a.wrapping_add((((a^b)&c)^b).wrapping_add(d).wrapping_add(x[2]).wrapping_add(0xfcefa3f8).rotate_left(9));
            c = d.wrapping_add((((d^a)&b)^a).wrapping_add(c).wrapping_add(x[7]).wrapping_add(0x676f02d9).rotate_left(14));
            b = c.wrapping_add((((c^d)&a)^d).wrapping_add(b).wrapping_add(x[12]).wrapping_add(0x8d2a4c8a).rotate_left(20));

            // round 3
            a = b.wrapping_add((b^c^d).wrapping_add(a).wrapping_add(x[5]).wrapping_add(0xfffa3942).rotate_left(4));
            d = a.wrapping_add((a^b^c).wrapping_add(d).wrapping_add(x[8]).wrapping_add(0x8771f681).rotate_left(11));
            c = d.wrapping_add((d^a^b).wrapping_add(c).wrapping_add(x[11]).wrapping_add(0x6d9d6122).rotate_left(16));
            b = c.wrapping_add((c^d^a).wrapping_add(b).wrapping_add(x[14]).wrapping_add(0xfde5380c).rotate_left(23));
            a = b.wrapping_add((b^c^d).wrapping_add(a).wrapping_add(x[1]).wrapping_add(0xa4beea44).rotate_left(4));
            d = a.wrapping_add((a^b^c).wrapping_add(d).wrapping_add(x[4]).wrapping_add(0x4bdecfa9).rotate_left(11));
            c = d.wrapping_add((d^a^b).wrapping_add(c).wrapping_add(x[7]).wrapping_add(0xf6bb4b60).rotate_left(16));
            b = c.wrapping_add((c^d^a).wrapping_add(b).wrapping_add(x[10]).wrapping_add(0xbebfbc70).rotate_left(23));
            a = b.wrapping_add((b^c^d).wrapping_add(a).wrapping_add(x[13]).wrapping_add(0x289b7ec6).rotate_left(4));
            d = a.wrapping_add((a^b^c).wrapping_add(d).wrapping_add(x[0]).wrapping_add(0xeaa127fa).rotate_left(11));
            c = d.wrapping_add((d^a^b).wrapping_add(c).wrapping_add(x[3]).wrapping_add(0xd4ef3085).rotate_left(16));
            b = c.wrapping_add((c^d^a).wrapping_add(b).wrapping_add(x[6]).wrapping_add(0x04881d05).rotate_left(23));
            a = b.wrapping_add((b^c^d).wrapping_add(a).wrapping_add(x[9]).wrapping_add(0xd9d4d039).rotate_left(4));
            d = a.wrapping_add((a^b^c).wrapping_add(d).wrapping_add(x[12]).wrapping_add(0xe6db99e5).rotate_left(11));
            c = d.wrapping_add((d^a^b).wrapping_add(c).wrapping_add(x[15]).wrapping_add(0x1fa27cf8).rotate_left(16));
            b = c.wrapping_add((c^d^a).wrapping_add(b).wrapping_add(x[2]).wrapping_add(0xc4ac5665).rotate_left(23));

            // round 4
            a = b.wrapping_add((c^(b|(!d))).wrapping_add(a).wrapping_add(x[0]).wrapping_add(0xf4292244).rotate_left(6));
            d = a.wrapping_add((b^(a|(!c))).wrapping_add(d).wrapping_add(x[7]).wrapping_add(0x432aff97).rotate_left(10));
            c = d.wrapping_add((a^(d|(!b))).wrapping_add(c).wrapping_add(x[14]).wrapping_add(0xab9423a7).rotate_left(15));
            b = c.wrapping_add((d^(c|(!a))).wrapping_add(b).wrapping_add(x[5]).wrapping_add(0xfc93a039).rotate_left(21));
            a = b.wrapping_add((c^(b|(!d))).wrapping_add(a).wrapping_add(x[12]).wrapping_add(0x655b59c3).rotate_left(6));
            d = a.wrapping_add((b^(a|(!c))).wrapping_add(d).wrapping_add(x[3]).wrapping_add(0x8f0ccc92).rotate_left(10));
            c = d.wrapping_add((a^(d|(!b))).wrapping_add(c).wrapping_add(x[10]).wrapping_add(0xffeff47d).rotate_left(15));
            b = c.wrapping_add((d^(c|(!a))).wrapping_add(b).wrapping_add(x[1]).wrapping_add(0x85845dd1).rotate_left(21));
            a = b.wrapping_add((c^(b|(!d))).wrapping_add(a).wrapping_add(x[8]).wrapping_add(0x6fa87e4f).rotate_left(6));
            d = a.wrapping_add((b^(a|(!c))).wrapping_add(d).wrapping_add(x[15]).wrapping_add(0xfe2ce6e0).rotate_left(10));
            c = d.wrapping_add((a^(d|(!b))).wrapping_add(c).wrapping_add(x[6]).wrapping_add(0xa3014314).rotate_left(15));
            b = c.wrapping_add((d^(c|(!a))).wrapping_add(b).wrapping_add(x[13]).wrapping_add(0x4e0811a1).rotate_left(21));
            a = b.wrapping_add((c^(b|(!d))).wrapping_add(a).wrapping_add(x[4]).wrapping_add(0xf7537e82).rotate_left(6));
            d = a.wrapping_add((b^(a|(!c))).wrapping_add(d).wrapping_add(x[11]).wrapping_add(0xbd3af235).rotate_left(10));
            c = d.wrapping_add((a^(d|(!b))).wrapping_add(c).wrapping_add(x[2]).wrapping_add(0x2ad7d2bb).rotate_left(15));
            b = c.wrapping_add((d^(c|(!a))).wrapping_add(b).wrapping_add(x[9]).wrapping_add(0xeb86d391).rotate_left(21));

            // add saved state
            a = a.wrapping_add(aa);
            b = b.wrapping_add(bb);
            c = c.wrapping_add(cc);
            d = d.wrapping_add(dd);

            i += MD5_BLOCK_SIZE;
        }
        
        self.digest[0] = a;
        self.digest[1] = b;
        self.digest[2] = c;
        self.digest[3] = d;
    }
}