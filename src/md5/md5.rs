//! MD5(Message Digest Algorithm v-5)  
//! RFC-1321  
//! https://www.cnblogs.com/mengsuenyan/p/12697709.html  

use crate::Digest;

pub(super) const MD5_BLOCK_SIZE: usize = 64;
pub(super) const MD5_DIGEST_BITS_LEN: usize = 16 << 3;
pub(super) const MD5_INIT: [u32; 4] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476];

#[derive(Clone)]
pub struct MD5 {
    pub(super) digest: [u32; 4],
    pub(super) buf: [u8; MD5_BLOCK_SIZE],
    pub(super) idx: usize,
    pub(super) len: usize,
    is_checked: bool,
}

impl MD5 {
    pub fn new() -> Self {
        MD5 {
            digest: MD5_INIT,
            buf: [0; MD5_BLOCK_SIZE],
            idx: 0,
            len: 0,
            is_checked: false,
        }
    }
}

impl Digest for MD5 {
    fn bits_len(&self) -> usize {
        MD5_DIGEST_BITS_LEN
    }

    fn write(&mut self, data: &[u8]) {
        let mut data = data;
        self.len += data.len();

        if self.idx > 0 {
            let min = std::cmp::min(MD5_BLOCK_SIZE - self.idx, data.len());
            let dst = &mut self.buf[self.idx..(self.idx+min)];
            let src = &data[0..min];
            dst.copy_from_slice(src);
            self.idx += min;

            if self.idx == MD5_BLOCK_SIZE {
                self.update(None);
                self.idx = 0;
            }

            data = &data[min..];
        }

        if data.len() >= MD5_BLOCK_SIZE {
            let n = data.len() & (!(MD5_BLOCK_SIZE - 1));
            let data_block = &data[0..n];
            self.update(Some(data_block));
            data = &data[n..];
        }

        if data.len() > 0 {
            let dst = &mut self.buf[..data.len()];
            dst.copy_from_slice(data);
            self.idx += data.len();
        }
        
        self.is_checked = false;
    }

    fn checksum(&mut self, digest: &mut Vec<u8>) {
        if !self.is_checked {
            // 补0x80, 然后填充0对齐到56字节, 然后按从低字节到高字节填充位长度
            let mut tmp = [0u8; 1+63+8];
            tmp[0] = 0x80;
            let pad_len = 55usize.wrapping_sub(self.len) % 64;
            let len = (self.len << 3) as u64;
            let src = len.to_le_bytes();
            let dst = &mut tmp[(1+pad_len)..(1+pad_len+8)];
            dst.copy_from_slice(&src[..]);
            self.write(&tmp[0..(1+pad_len+8)]);
            self.is_checked = true;
        }
        
        digest.clear();
        self.digest.iter().rev().for_each(|&e| {
            digest.extend(e.to_be_bytes().iter());
        });
    }

    fn reset(&mut self) {
        *self = MD5::new();
    }
}

#[cfg(test)]
mod tests {
    use crate::Digest;

    #[test]
    fn md5() {
        let cases = [
            (0xd41d8cd98f00b204e9800998ecf8427eu128, ""),
            (0x0cc175b9c0f1b6a831c399e269772661u128, "a"),
            (0x187ef4436122d1cc2f40dc2b92f0eba0u128, "ab"),
            (0x900150983cd24fb0d6963f7d28e17f72u128, "abc"),
            (0xe2fc714c4727ee9395f324cd2e7f331fu128, "abcd"),
            (0xab56b4d92b40713acc5af89985d4b786u128, "abcde"),
            (0xe80b5017098950fc58aad83c8c14978eu128, "abcdef"),
            (0x7ac66c0f148de9519b8bd264312c4d64u128, "abcdefg"),
            (0xe8dc4081b13434b45189a720b77b6818u128, "abcdefgh"),
            (0x8aa99b1f439ff71293e95357bac6fd94u128, "abcdefghi"),
            (0xa925576942e94b2ef57a066101b48876u128, "abcdefghij"),
            (0xd747fc1719c7eacb84058196cfe56d57u128, "Discard medicine more than two years old."),
            (0xbff2dcb37ef3a44ba43ab144768ca837u128, "He who has a shady past knows that nice guys finish last."),
            (0x0441015ecb54a7342d017ed1bcfdbea5u128, "I wouldn't marry him with a ten foot pole."),
            (0x9e3cac8e9e9757a60c3ea391130d3689u128, "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"),
            (0xa0f04459b031f916a59a35cc482dc039u128, "The days of the digital watch are numbered.  -Tom Stoppard"),
            (0xe7a48e0fe884faf31475d2a04b1362ccu128, "Nepal premier won't resign."),
            (0x637d2fe925c07c113800509964fb0e06u128, "For every action there is an equal and opposite government program."),
            (0x834a8d18d5c6562119cf4c7f5086cb71u128, "His money is twice tainted: 'taint yours and 'taint mine."),
            (0xde3a4d2fd6c73ec2db2abad23b444281u128, "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"),
            (0xacf203f997e2cf74ea3aff86985aefafu128, "It's a tiny change to the code and not completely disgusting. - Bob Manchek"),
            (0xe1c1384cb4d2221dfdd7c795a4222c9au128, "size:  a.out:  bad magic"),
            (0xc90f3ddecc54f34228c063d7525bf644u128, "The major problem is with sendmail.  -Mark Horton"),
            (0xcdf7ab6c1fd49bd9933c43f3ea5af185u128, "Give me a rock, paper and scissors and I will move the world.  CCFestoon"),
            (0x83bc85234942fc883c063cbd7f0ad5d0u128, "If the enemy is within range, then so are you."),
            (0x277cbe255686b48dd7e8f389394d9299u128, "It's well we cannot hear the screams/That we create in others' dreams."),
            (0xfd3fb0a7ffb8af16603f3d3af98f8e1fu128, "You remind me of a TV show, but that's all right: I watch it anyway."),
            (0x469b13a78ebf297ecda64d4723655154u128, "C is as portable as Stonehedge!!"),
            (0x63eb3a2f466410104731c4b037600110u128, "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"),
            (0x72c2ed7592debca1c90fc0100f931a2fu128, "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"),
            (0x132f7619d33b523b1d9e5bd8e0928355u128, "How can you write a big system without C++?  -Paul Glick"),
        ];

        let mut md5 = super::MD5::new();
        let mut digest = Vec::with_capacity(md5.bits_len() >> 3);
        cases.iter().for_each(|e| {
            md5.write((e.1).as_bytes());
            md5.checksum(&mut digest);
            println!("{:#x},{:#x}", e.0, digest.iter().fold(0, |sum, &d| { (d as u128) | (sum << 8)}));
            assert_eq!(e.0, digest.iter().enumerate().fold(0, |sum, (i, &d)| { sum | ((d as u128) << (i << 3))}), "cases: {}", e.1);
            md5.reset();
        })
    }
}
