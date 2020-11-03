use crate::{TDES, CMAC, Digest};
use crate::aes::AES;

#[test]
fn cmac_tdes() {
    // (key, [(plaintext, mac)]
    let cases = [
        (
            (0x0123456789ABCDEFu64, 0x23456789ABCDEF01u64, 0x456789ABCDEF0123u64),
            vec![
                (vec![], vec![0x7DB0D37Du32, 0xF936C550]),
                (vec![0x6BC1BEE2u32, 0x2E409F96, 0xE93D7E11, 0x7393172A], vec![0x30239CF1, 0xF52E6609]),
                (vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57], vec![0x6C9F3EE4, 0x923F6BE2]),
                (vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51], vec![0x99429BD0, 0xBF7904E5]),
            ],
        ),
        (
            (0x0123456789ABCDEFu64, 0x23456789ABCDEF01u64, 0x0123456789ABCDEFu64),
            vec![
                (vec![], vec![0x79CE52A7, 0xF786A960]),
                (vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A], vec![0xCC18A0B7, 0x9AF2413B]),
                (vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57], vec![0xC06D377E, 0xCD101969]),
                (vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51,], vec![0x9CD33580, 0xF9B64DFB,]),
            ],
        )
    ];
    
    let (mut tgt_mac, mut buf) = (Vec::with_capacity(8), Vec::with_capacity(8));
    for (i, ele) in cases.iter().enumerate() {
        let tdes = TDES::new(ele.0.0.to_be_bytes(), ele.0.1.to_be_bytes(), ele.0.2.to_be_bytes());
        let mut cmac = CMAC::new(tdes).unwrap();
        
        for (j, (sample, tag)) in ele.1.iter().enumerate() {
            buf.clear();
            sample.iter().for_each(|&x| {
                x.to_be_bytes().iter().for_each(|&y| {buf.push(y);});
            });
            cmac.write(buf.as_slice());
            cmac.checksum(&mut buf);
            
            tgt_mac.clear();
            tag.iter().for_each(|&x| {
                x.to_be_bytes().iter().for_each(|&y| {
                    tgt_mac.push(y);
                });
            });
            
            assert_eq!(buf.as_slice(), tgt_mac.as_slice(), "case: {}-{}", i, j);
        }
    }
}

#[test]
fn cmac_aes() {

    // (key, [(plaintext, mac)]
    let cases = [
        (
            vec![0x2B7E1516u32, 0x28AED2A6, 0xABF71588, 0x09CF4F3C,],
            vec![
                (vec![], vec![0xBB1D6929u32, 0xE9593728, 0x7FA37D12, 0x9B756746,]),
                (vec![0x6BC1BEE2u32, 0x2E409F96, 0xE93D7E11, 0x7393172A,], vec![0x070A16B4, 0x6B4D4144, 0xF79BDD9D, 0xD04A287C,]),
                (vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57], vec![0x7D85449E, 0xA6EA19C8, 0x23A7BF78, 0x837DFADE,]),
                (vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51, 0x30C81C46, 0xA35CE411, 0xE5FBC119, 0x1A0A52EF, 0xF69F2445, 0xDF4F9B17, 0xAD2B417B, 0xE66C3710,],
                 vec![0x51F0BEBF, 0x7E3B9D92, 0xFC497417, 0x79363CFE,]),
            ],
        ),
        (
            vec![0x8E73B0F7, 0xDA0E6452, 0xC810F32B, 0x809079E5, 0x62F8EAD2, 0x522C6B7B,], 
            vec![
                (vec![], vec![0xD17DDF46, 0xADAACDE5, 0x31CAC483, 0xDE7A9367,]),
                (vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A,], vec![0x9E99A7BF, 0x31E71090, 0x0662F65E, 0x617C5184,]),
                (vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57,], vec![0x3D75C194, 0xED960704, 0x44A9FA7E, 0xC740ECF8,]),
                (vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51, 0x30C81C46, 0xA35CE411, 0xE5FBC119, 0x1A0A52EF, 0xF69F2445, 0xDF4F9B17, 0xAD2B417B, 0xE66C3710,],
                    vec![0xA1D5DF0E, 0xED790F79, 0x4D775896, 0x59F39A11,]),
            ],
        ),
        (
            vec![0x603DEB10, 0x15CA71BE, 0x2B73AEF0, 0x857D7781, 0x1F352C07, 0x3B6108D7, 0x2D9810A3, 0x0914DFF4,],
            vec![
                (vec![], vec![0x028962F6, 0x1B7BF89E, 0xFC6B551F, 0x4667D983,]),
                (vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A,], vec![0x28A7023F, 0x452E8F82, 0xBD4BF28D, 0x8C37C35C,]),
                (vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57,], vec![0x156727DC, 0x0878944A, 0x023C1FE0, 0x3BAD6D93,]),
                (vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51, 0x30C81C46, 0xA35CE411, 0xE5FBC119, 0x1A0A52EF, 0xF69F2445, 0xDF4F9B17, 0xAD2B417B, 0xE66C3710,],
                    vec![0xE1992190, 0x549F6ED5, 0x696A2C05, 0x6C315410,]),
            ],
        )
    ];
    
    let (mut tgt_mac, mut buf) = (Vec::with_capacity(8), Vec::with_capacity(8));
    for (i, ele) in cases.iter().enumerate() {
        buf.clear();
        ele.0.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                buf.push(y);
            });
        });
        let aes = AES::new(buf.clone()).unwrap();
        let mut cmac = CMAC::new(aes).unwrap();

        for (j, (sample, tag)) in ele.1.iter().enumerate() {
            buf.clear();
            sample.iter().for_each(|&x| {
                x.to_be_bytes().iter().for_each(|&y| {buf.push(y);});
            });
            cmac.write(buf.as_slice());
            cmac.checksum(&mut buf);

            tgt_mac.clear();
            tag.iter().for_each(|&x| {
                x.to_be_bytes().iter().for_each(|&y| {
                    tgt_mac.push(y);
                });
            });

            assert_eq!(buf.as_slice(), tgt_mac.as_slice(), "case: {}-{}", i, j);
        }
    }
}