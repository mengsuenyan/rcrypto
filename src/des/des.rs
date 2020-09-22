//! DES(Data Encryption Standard)  
//! FIPS 46-3  
//! https://www.cnblogs.com/mengsuenyan/p/12905365.html   
//! 

use crate::des::const_tables as mct;
use crate::{Cipher, CryptoError, CryptoErrorKind};

/// DES
pub struct DES {
    ks: [u64; 16],
}

impl DES {
    pub fn new(key: [u8; 8]) -> DES {
        DES {
            ks: DES::key_schedule(key),
        }
    }

    #[inline]
    fn cvt_slice_to_u64(src: &[u8]) -> u64 {
        let v = [src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7]];
        #[cfg(target_endian = "little")]
            {
                u64::from_le_bytes(v)
            }
        #[cfg(target_endian = "big")]
            {
                u64::from_be_bytes(v)
            }
    }

    #[inline]
    fn cvt_to_bytes(src: u64) -> [u8; 8] {
        #[cfg(target_endian = "little")]
            {
                src.to_le_bytes()
            }
        #[cfg(target_endian = "big")]
            {
                src.to_be_bytes()
            }
    }

    #[inline]
    fn cvt_from_bytes(src: [u8; 8]) -> u64 {
        #[cfg(target_endian = "little")]
            {
                u64::from_le_bytes(src)
            }
        #[cfg(target_endian = "big")]
            {
                u64::from_be_bytes(src)
            }
    }

    fn crypt_block(&self, dst: &mut [u8; 8], src: &[u8], is_encrypt: bool){
        let data = DES::permute(DES::cvt_slice_to_u64(src), mct::DES_IP.as_ref());
        let (mut l_pre, mut r_pre) = (data & (u32::max_value() as u64), data >> 32);

        if is_encrypt {
            for i in 0..16 {
                let tmp = r_pre;
                r_pre = l_pre ^ DES::feistel(r_pre, self.ks[i]);
                l_pre = tmp;
            }
        } else {
            for i in 0..16 {
                let tmp = r_pre;
                r_pre = l_pre ^ DES::feistel(r_pre, self.ks[15 - i]);
                l_pre = tmp;
            }
        }

        let pre_output = (l_pre << 32) | r_pre;
        *dst = DES::cvt_to_bytes(DES::permute(pre_output, mct::DES_IIP.as_ref()));
    }

    /// 输入32位的R和48位的k, 输出32位  
    fn feistel(r: u64, k: u64) -> u64 {
        let r_p = DES::f_expand(r);
        let t = r_p ^ k;
        let s_p = DES::f_sbox(t);
        DES::permute(s_p, mct::DES_P.as_ref())
    }

    /// in: 32 out: 48  
    fn f_expand(r: u64) -> u64 {
        DES::permute(r, mct::DES_E.as_ref())
    }

    #[inline]
    fn sbox_idx(t: u8) -> usize {
        let t = t as usize;
        let (m, n) = ((t & 0x1) + ((t >> 4) & 0x2), (t >> 1) & 0xf);
        (m << 4) + n
    }

    /// in: 48, out: 32  
    fn f_sbox(t: u64) -> u64 {
        let mut output = 0u64;
        let e = DES::cvt_to_bytes(t);

        // 11111111 .... 11111111
        // 0        ....  5
        // 11111122 .... 77888888
        let b1 = e[0] >> 2;
        let b2 = ((e[0] & 3) << 4) + (e[1] >> 4);
        let b3 = ((e[1] & 15) << 2) + (e[2] >> 6);
        let b4 = e[2] & 63;
        let b5 = e[3] >> 2;
        let b6 = ((e[3] & 3) << 4) + (e[4] >> 4);
        let b7 = ((e[4] & 15) << 2) + (e[5] >> 6);
        let b8 = e[5] & 63;
        output |= ((mct::DES_S[0][DES::sbox_idx(b1)] as u64) << 4) + (mct::DES_S[1][DES::sbox_idx(b2)] as u64);
        output |= (((mct::DES_S[2][DES::sbox_idx(b3)] as u64) << 4) + (mct::DES_S[3][DES::sbox_idx(b4)] as u64)) << 8;
        output |= (((mct::DES_S[4][DES::sbox_idx(b5)] as u64) << 4) + (mct::DES_S[5][DES::sbox_idx(b6)] as u64)) << 16;
        output |= (((mct::DES_S[6][DES::sbox_idx(b7)] as u64) << 4) + (mct::DES_S[7][DES::sbox_idx(b8)] as u64)) << 24;

        output
    }

    /// 生成每一轮的加密密钥(48位)  
    fn key_schedule(key: [u8; 8]) -> [u64; 16] {
        const ROWS: usize = 16;
        let mut output = [0u64; ROWS];

        let key = DES::cvt_from_bytes(key);
        let k_pre = DES::permute(key, mct::DES_PC1.as_ref());
        output.iter_mut().enumerate().fold(k_pre, |k, (i, o)| {
            let tmp = DES::ks_rotate(k, mct::DES_LS[i]);
            *o = DES::permute(tmp, mct::DES_PC2.as_ref());
            tmp
        });

        output
    }

    /// p: key -> K_p, output: (C0 << 28) | D0;  
    fn permute(key: u64, permutation: &[u8]) -> u64 {
        permutation.iter().enumerate().fold(0, |k_p, (i, &ele)| {
            let b = (key >> ele) & 0x1;
            k_p | (b << i)
        })
    }

    /// key=(C<<28)|D, C<<<cl, D<<<cla, output: C<<28|D  
    /// note: 针对DES_LS, 故未做边界检查  
    /// note: 编号是按照从低字节到高字节, 从左往右排序的, 见const_table注释;  
    fn ks_rotate(key: u64, cl: u8) -> u64 {
        let (sl, sr) = (cl, 8 - cl);
        let v = DES::cvt_to_bytes(key);
        let mut output = 0;
        output |= ((v[0] << sl) | (v[1] >> sr)) as u64;
        output |= (((v[1] << sl) | (v[2] >> sr)) as u64) << 8;
        output |= (((v[2] << sl) | (v[3] >> sr)) as u64) << 16;
        let tmp = v[3] << (4 + sl);
        output |= ((((v[3] & 0xf0) << sl) | ((v[0] >> sr) << 4) | (tmp >> 4) | (v[4] >> sr)) as u64) << 24;
        output |= (((v[4] << sl) | (v[5] >> sr)) as u64) << 32;
        output |= (((v[5] << sl) | (v[6] >> sr)) as u64) << 40;
        let tmp = v[3] << 4;
        output |= (((v[6] << sl) | (tmp >> (8 - sl))) as u64) << 48;

        output
    }
}

impl Cipher for DES {
    fn block_size(&self) -> Option<usize> {
        Some(mct::DES_BLOCK_SIZE)
    }

    fn encrypt(&self, dst: &mut Vec<u8>, data_block: &[u8]) -> std::result::Result<usize, CryptoError> {
        if data_block.len() == mct::DES_BLOCK_SIZE {
            let mut output = [0u8; 8];
            self.crypt_block(&mut output, data_block, true);
            dst.clear();
            dst.append(&mut output.to_vec());
            Ok(output.len())
        } else {
            Err(CryptoError::new(CryptoErrorKind::InvalidParameter, 
                format!("Wrong block len: {}, it must be the {}", data_block.len(), mct::DES_BLOCK_SIZE)))
        }
    }

    fn decrypt(&self, dst: &mut Vec<u8>, cipher_text: &[u8]) -> std::result::Result<usize, CryptoError> {
        if cipher_text.len() == mct::DES_BLOCK_SIZE {
            let mut output = [0u8; 8];
            self.crypt_block(&mut output, cipher_text, false);
            dst.clear();
            dst.append(&mut output.to_vec());
            Ok(output.len())
        } else {
            Err(CryptoError::new(CryptoErrorKind::InvalidParameter,
                                 format!("Wrong block len: {}, it must be the {}", cipher_text.len(), mct::DES_BLOCK_SIZE)))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Cipher;

    // these test cases come from golang sources
    #[test]
    fn des() {
        let cases = [
            ([0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
             [0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
             [0x8cu8, 0xa6, 0x4d, 0xe9, 0xc1, 0xb1, 0x23, 0xa7],),
            ([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
             [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
             [0x35, 0x55, 0x50, 0xb2, 0x15, 0x0e, 0x24, 0x51],),
            ([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
             [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
             [0x61, 0x7b, 0x3a, 0x0c, 0xe8, 0xf0, 0x71, 0x00]),
            ([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
             [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
             [0x92, 0x31, 0xf2, 0x36, 0xff, 0x9a, 0xa9, 0x5c]),
            ([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
             [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
             [0xca, 0xaa, 0xaf, 0x4d, 0xea, 0xf1, 0xdb, 0xae]),
            ([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
             [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
             [0x73, 0x59, 0xb2, 0x16, 0x3e, 0x4e, 0xdc, 0x58]),
            ([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
             [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
             [0x6d, 0xce, 0x0d, 0xc9, 0x00, 0x65, 0x56, 0xa3]),
            ([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
             [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
             [0x9e, 0x84, 0xc5, 0xf3, 0x17, 0x0f, 0x8e, 0xff]),
            ([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
             [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
             [0xd5, 0xd4, 0x4f, 0xf7, 0x20, 0x68, 0x3d, 0x0d]),
            ([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
             [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
             [0x59, 0x73, 0x23, 0x56, 0xf3, 0x6f, 0xde, 0x06]),
            ([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
             [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
             [0x56, 0xcc, 0x09, 0xe7, 0xcf, 0xdc, 0x4c, 0xef]),
            ([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
             [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
             [0x12, 0xc6, 0x26, 0xaf, 0x05, 0x8b, 0x43, 0x3b]),
            ([0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
             [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
             [0xa6, 0x8c, 0xdc, 0xa9, 0x0c, 0x90, 0x21, 0xf9]),
            ([0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
             [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
             [0x2a, 0x2b, 0xb0, 0x08, 0xdf, 0x97, 0xc2, 0xf2]),
            ([0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
             [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
             [0xed, 0x39, 0xd9, 0x50, 0xfa, 0x74, 0xbc, 0xc4]),
            ([0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
             [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
             [0xa9, 0x33, 0xf6, 0x18, 0x30, 0x23, 0xb3, 0x10]),
            ([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
             [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11],
             [0x17, 0x66, 0x8d, 0xfc, 0x72, 0x92, 0x53, 0x2d]),
            ([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
             [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
             [0xb4, 0xfd, 0x23, 0x16, 0x47, 0xa5, 0xbe, 0xc0]),
            ([0x0e, 0x32, 0x92, 0x32, 0xea, 0x6d, 0x0d, 0x73],
             [0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87],
             [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            ([0x73, 0x65, 0x63, 0x52, 0x33, 0x74, 0x24, 0x3b], // "secR3t$;"
             [0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x31, 0x32], // "a test12"
             [0x37, 0x0d, 0xee, 0x2c, 0x1f, 0xb4, 0xf7, 0xa5]),
            ([0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68], // "abcdefgh"
             [0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68], // "abcdefgh"
             [0x2a, 0x8d, 0x69, 0xde, 0x9d, 0x5f, 0xdf, 0xf9]),
            ([0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68], // "abcdefgh"
             [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38], // "12345678"
             [0x21, 0xc6, 0x0d, 0xa5, 0x34, 0x24, 0x8b, 0xce]),
            ([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38], // "12345678"
             [0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68], // "abcdefgh"
             [0x94, 0xd4, 0x43, 0x6b, 0xc3, 0xb5, 0xb6, 0x93]),
            ([0x1f, 0x79, 0x90, 0x5f, 0x88, 0x01, 0xc8, 0x88], // random
             [0xc7, 0x46, 0x18, 0x73, 0xaf, 0x48, 0x5f, 0xb3], // random
             [0xb0, 0x93, 0x50, 0x88, 0xf9, 0x92, 0x44, 0x6a]),
            ([0xe6, 0xf4, 0xf2, 0xdb, 0x31, 0x42, 0x53, 0x01], // random
             [0xff, 0x3d, 0x25, 0x50, 0x12, 0xe3, 0x4a, 0xc5], // random
             [0x86, 0x08, 0xd3, 0xd1, 0x6c, 0x2f, 0xd2, 0x55]),
            ([0x69, 0xc1, 0x9d, 0xc1, 0x15, 0xc5, 0xfb, 0x2b], // random
             [0x1a, 0x22, 0x5c, 0xaf, 0x1f, 0x1d, 0xa3, 0xf9], // random
             [0x64, 0xba, 0x31, 0x67, 0x56, 0x91, 0x1e, 0xa7]),
            ([0x6e, 0x5e, 0xe2, 0x47, 0xc4, 0xbf, 0xf6, 0x51], // random
             [0x11, 0xc9, 0x57, 0xff, 0x66, 0x89, 0x0e, 0xf0], // random
             [0x94, 0xc5, 0x35, 0xb2, 0xc5, 0x8b, 0x39, 0x72]),
        ];

        for ele in cases.iter() {
            let cipher = super::DES::new(ele.0);
            let (mut encrypt, mut decrypt) = (Vec::with_capacity(8), Vec::with_capacity(8));

            cipher.encrypt(&mut encrypt, ele.1.as_ref()).unwrap();
            cipher.decrypt(&mut decrypt, encrypt.as_slice()).unwrap();
            assert_eq!(encrypt, ele.2.to_vec());
            assert_eq!(decrypt, ele.1.to_vec());
        }
    }

    /// 将原始表转换为兼容表  
    #[allow(unused)]
    fn compute_table() {
        fn inner_cpt(tb: &[u8]) -> Vec<u8> {
            let mut v = Vec::with_capacity(tb.len());
            // 8个一组, 每组反转
            let rows = tb.len() / 8;
            for i in 0..rows {
                let row = &tb[(i*8)..((i+1)*8)];
                for &ele in row.iter().rev() {
                    let rem = (ele - 1) / 8;
                    let te = rem * 8 + ((rem + 1) * 8 - ele);
                    v.push(te);
                }
            }

            v
        }

        let des_ip = inner_cpt(super::mct::DES_IP.as_ref());
        println!("des_ip:\n{:?}", des_ip);
        let des_iip = inner_cpt(super::mct::DES_IIP.as_ref());
        println!("des_iip:\n{:?}", des_iip);
        let des_e = inner_cpt(super::mct::DES_E.as_ref());
        println!("des_e:\n{:?}", des_e);
        let des_p = inner_cpt(super::mct::DES_P.as_ref());
        println!("des_p:\n{:?}", des_p);
        let des_pc2 = inner_cpt(super::mct::DES_PC2.as_ref());
        println!("des_pc2:\n{:?}", des_pc2);
    }
}
