use crate::cipher_mode::{ECB, EmptyPadding, EncryptStream, DecryptStream, CBC, DefaultInitialVec, CFB, OFB, DefaultCounter, CTR};
use crate::{TDES, Cipher};
use rmath::rand::{CryptoRand, DefaultSeed};
use crate::aes::AES;

#[test]
fn ecb_aes() {
    let cases = [
        (
            vec![0x2B7E1516u32, 0x28AED2A6, 0xABF71588, 0x09CF4F3C,],
            vec![0x6BC1BEE2u32, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51, 0x30C81C46, 0xA35CE411, 0xE5FBC119, 0x1A0A52EF, 0xF69F2445, 0xDF4F9B17, 0xAD2B417B, 0xE66C3710,],
            vec![0x3AD77BB4u32, 0x0D7A3660, 0xA89ECAF3, 0x2466EF97, 0xF5D3D585, 0x03B9699D, 0xE785895A, 0x96FDBAAF, 0x43B1CD7F, 0x598ECE23, 0x881B00E3, 0xED030688, 0x7B0C785E, 0x27E8AD3F, 0x82232071, 0x04725DD4,],
        ),
    ];
    
    let (mut buf, mut tmp) = (Vec::with_capacity(16), Vec::with_capacity(16));
    for (i, ele) in cases.iter().enumerate() {
        buf.clear();
        ele.0.iter().for_each(|&x| {buf.append(&mut x.to_be_bytes().to_vec());});
        let aes = AES::new(buf.clone()).unwrap();
        let cm = ECB::new(aes, EmptyPadding::new());
        let (mut cm_encrypt, mut cm_decrypt) = (cm.clone().encrypt_stream(), cm.decrypt_stream());

        ele.1.iter().for_each(|&x| {
            cm_encrypt.write(x.to_be_bytes().as_ref()).unwrap();
        });

        buf.clear();
        cm_encrypt.finish().unwrap().draw_off(&mut buf);

        tmp.clear();
        ele.2.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });

        assert_eq!(tmp, buf, "encrypt-case: {}", i);

        ele.2.iter().for_each(|&x| {
            cm_decrypt.write(x.to_be_bytes().as_ref()).unwrap();
        });

        buf.clear();
        cm_decrypt.finish().unwrap().draw_off(&mut buf);
        tmp.clear();
        ele.1.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        assert_eq!(tmp, buf, "decrypt-case: {}", i);
    }
}

#[test]
fn ecb_tdes() {
    let cases = [
        (
            (0x0123456789ABCDEFu64, 0x23456789ABCDEF01u64, 0x456789ABCDEF0123u64),
            vec![0x6BC1BEE22E409F96u64, 0xE93D7E117393172A, 0xAE2D8A571E03AC9C, 0x9EB76FAC45AF8E51,],
            vec![0x714772F339841D34u64, 0x267FCC4BD2949CC3, 0xEE11C22A576A3038, 0x76183F99C0B6DE87],
        ),
        (
            (0x0123456789ABCDEFu64, 0x23456789ABCDEF01u64, 0x0123456789ABCDEFu64),
            vec![0x6BC1BEE22E409F96u64, 0xE93D7E117393172A, 0xAE2D8A571E03AC9C, 0x9EB76FAC45AF8E51,],
            vec![0x06EDE3D82884090A, 0xFF322C19F0518486, 0x730576972A666E58, 0xB6C88CF107340D3D],
        )
    ];
    
    let (mut buf, mut tmp) = (Vec::with_capacity(16), Vec::with_capacity(16));
    for (i, ele) in cases.iter().enumerate() {
        let tdes = TDES::new(ele.0.0.to_be_bytes(), ele.0.1.to_be_bytes(), ele.0.2.to_be_bytes());
        let cm = ECB::new(tdes, EmptyPadding::new());
        let (mut cm_encrypt, mut cm_decrypt) = (cm.clone().encrypt_stream(), cm.decrypt_stream());
        
        ele.1.iter().for_each(|&x| {
            cm_encrypt.write(x.to_be_bytes().as_ref()).unwrap();
        });
        
        buf.clear();
        cm_encrypt.finish().unwrap().draw_off(&mut buf);
        
        tmp.clear();
        ele.2.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        
        assert_eq!(tmp, buf, "encrypt-case: {}", i);
        
        ele.2.iter().for_each(|&x| {
            cm_decrypt.write(x.to_be_bytes().as_ref()).unwrap();
        });
        
        buf.clear();
        cm_decrypt.finish().unwrap().draw_off(&mut buf);
        tmp.clear();
        ele.1.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        assert_eq!(tmp, buf, "decrypt-case: {}", i);
    }
}

#[test]
fn cbc_test() {
    let cases = [
        (
            (0x0123456789ABCDEFu64, 0x23456789ABCDEF01u64, 0x456789ABCDEF0123u64, 0xF69F2445DF4F9B17u64),
            vec![0x6BC1BEE2u32, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51,],
            vec![0x2079C3D5u32, 0x3AA763E1, 0x93B79E25, 0x69AB5262, 0x51657048, 0x1F25B50F, 0x73C0BDA8, 0x5C8E0DA7,],
        ),
        (
            (0x0123456789ABCDEFu64, 0x23456789ABCDEF01u64, 0x0123456789ABCDEFu64, 0xF69F2445DF4F9B17u64),
            vec![0x6BC1BEE2u32, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51,],
            vec![0x7401CE1Eu32, 0xAB6D003C, 0xAFF84BF4, 0x7B36CC21, 0x54F0238F, 0x9FFECD8F, 0x6ACF1183, 0x92B45581,],
        ),
    ];
    
    let (mut buf, mut tmp) = (Vec::with_capacity(16), Vec::with_capacity(16));
    for (i, ele) in cases.iter().enumerate() {
        let tdes = TDES::new(ele.0.0.to_be_bytes(), ele.0.1.to_be_bytes(), ele.0.2.to_be_bytes());
        let iv = DefaultInitialVec::new(&tdes, CryptoRand::new(&DefaultSeed::<u32>::new().unwrap()).unwrap());
        let mut cm = CBC::new(tdes, EmptyPadding, iv).unwrap();
        cm.set_iv(ele.0.3.to_be_bytes().to_vec()).unwrap();
        
        let cm_en = cm.clone();
        tmp.clear();
        ele.1.iter().for_each(|&x| {
            tmp.append(&mut x.to_be_bytes().to_vec());
        });
        cm_en.encrypt(&mut buf, tmp.as_slice()).unwrap();
        tmp.clear();
        ele.2.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        assert_eq!(tmp, buf, "encrypt-case: {}", i);
        
        let cm_de = cm.clone();
        tmp.clear();
        ele.2.iter().for_each(|&x| {
            tmp.append(&mut x.to_be_bytes().to_vec());
        });
        cm_de.decrypt(&mut buf, tmp.as_slice()).unwrap();
        tmp.clear();
        ele.1.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        assert_eq!(tmp, buf, "encrypt-case: {}", i);
        
        let (mut cm_encrypt, mut cm_decrypt) = (cm.clone().encrypt_stream(), cm.clone().decrypt_stream());
        
        ele.1.iter().for_each(|&x| {
            cm_encrypt.write(x.to_be_bytes().as_ref()).unwrap();
        });
        
        buf.clear();
        cm_encrypt.finish().unwrap().draw_off(&mut buf);
        
        tmp.clear();
        ele.2.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        
        assert_eq!(tmp, buf, "encrypt-case: {}", i);
        
        ele.2.iter().for_each(|&x| {
            cm_decrypt.write(x.to_be_bytes().as_ref()).unwrap();
        });
        
        buf.clear();
        cm_decrypt.finish().unwrap().draw_off(&mut buf);
        tmp.clear();
        ele.1.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        assert_eq!(tmp, buf, "decrypt-case: {}", i);
    }
}

#[test]
fn cfb_test() {
    let cases = [
        (
            (0x0123456789ABCDEFu64, 0x23456789ABCDEF01u64, 0x456789ABCDEF0123u64, 0xF69F2445DF4F9B17u64, 8usize),
            vec![0x6BC1BEE2u32, 0x2E409F96,],
            vec![0x07951B72u32, 0x9DC23AB4,],
        ),
        (
            (0x0123456789ABCDEFu64, 0x23456789ABCDEF01u64, 0x456789ABCDEF0123u64, 0xF69F2445DF4F9B17u64, 64usize),
            vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51,],
            vec![0x078BB74E, 0x59CE7ED6, 0x7666DE9C, 0xF95EAF3F, 0xE9ED6BB4, 0x60F45152, 0x8A5F9FE4, 0xED710918,],
        ),
        (
            (0x0123456789ABCDEFu64, 0x23456789ABCDEF01u64, 0x0123456789ABCDEFu64, 0xF69F2445DF4F9B17u64, 8usize),
            vec![0x6BC1BEE2u32, 0x2E409F96,],
            vec![0x61D86D9A, 0xEE9693FD,],
        ),
        (
            (0x0123456789ABCDEFu64, 0x23456789ABCDEF01u64, 0x0123456789ABCDEFu64, 0xF69F2445DF4F9B17u64, 64usize),
            vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51,],
            vec![0x6195B9C2, 0xC39909C5, 0x2EF31366, 0x7B5A66AF, 0x688672A3, 0x993AEAE5, 0x5B931AE2, 0x4EE24C5C,],
        ),
    ];
    
    let (mut buf, mut tmp) = (Vec::with_capacity(16), Vec::with_capacity(16));
    for (i, ele) in cases.iter().enumerate() {
        let tdes = TDES::new(ele.0.0.to_be_bytes(), ele.0.1.to_be_bytes(), ele.0.2.to_be_bytes());
        let iv = DefaultInitialVec::new(&tdes, CryptoRand::new(&DefaultSeed::<u32>::new().unwrap()).unwrap());
        let mut cm = CFB::new(tdes, EmptyPadding::new(), iv, ele.0.4).unwrap();
        cm.set_iv(ele.0.3.to_be_bytes().to_vec()).unwrap();

        let cm_en = cm.clone();
        tmp.clear();
        ele.1.iter().for_each(|&x| {
            tmp.append(&mut x.to_be_bytes().to_vec());
        });
        cm_en.encrypt(&mut buf, tmp.as_slice()).unwrap();
        tmp.clear();
        ele.2.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        assert_eq!(tmp, buf, "encrypt-case: {}", i);
        
        let cm_de = cm.clone();
        tmp.clear();
        ele.2.iter().for_each(|&x| {
            tmp.append(&mut x.to_be_bytes().to_vec());
        });
        cm_de.decrypt(&mut buf, tmp.as_slice()).unwrap();
        tmp.clear();
        ele.1.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        assert_eq!(tmp, buf, "decrypt-case: {}", i);
        
        let (mut cm_encrypt, mut cm_decrypt) = (cm.clone().encrypt_stream(), cm.clone().decrypt_stream());
        
        ele.1.iter().for_each(|&x| {
            cm_encrypt.write(x.to_be_bytes().as_ref()).unwrap();
        });
        
        buf.clear();
        cm_encrypt.finish().unwrap().draw_off(&mut buf);
        
        tmp.clear();
        ele.2.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        
        assert_eq!(tmp, buf, "encrypt-case: {}", i);
        
        ele.2.iter().for_each(|&x| {
            cm_decrypt.write(x.to_be_bytes().as_ref()).unwrap();
        });
        
        buf.clear();
        cm_decrypt.finish().unwrap().draw_off(&mut buf);
        tmp.clear();
        ele.1.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        assert_eq!(tmp, buf, "decrypt-case: {}", i);
    }
}

#[test]
fn ofb_test() {
    let cases = [
        (
            (0x0123456789ABCDEFu64, 0x23456789ABCDEF01u64, 0x456789ABCDEF0123u64, 0xF69F2445DF4F9B17u64),
            vec![0x6BC1BEE2u32, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51,],
            vec![0x078BB74Eu32, 0x59CE7ED6, 0x267E1206, 0x92667DA1, 0xA58662D7, 0xE04CBC64, 0x2144D55C, 0x03DB5AEE,],
        ),
        (
            (0x0123456789ABCDEFu64, 0x23456789ABCDEF01u64, 0x0123456789ABCDEFu64, 0xF69F2445DF4F9B17u64),
            vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51,],
            vec![0x6195B9C2, 0xC39909C5, 0x3334BA77, 0xFFDCCC80, 0xE485E85F, 0x0A63E764, 0x6D8D732E, 0x33241F94,],
        ),
    ];
    
    let (mut buf, mut tmp) = (Vec::with_capacity(16), Vec::with_capacity(16));
    for (i, ele) in cases.iter().enumerate() {
        let tdes = TDES::new(ele.0.0.to_be_bytes(), ele.0.1.to_be_bytes(), ele.0.2.to_be_bytes());
        let iv = DefaultInitialVec::new(&tdes, CryptoRand::new(&DefaultSeed::<u32>::new().unwrap()).unwrap());
        let mut cm = OFB::new(tdes, iv).unwrap();
        cm.set_iv(ele.0.3.to_be_bytes().to_vec()).unwrap();

        let cm_en = cm.clone();
        tmp.clear();
        ele.1.iter().for_each(|&x| {
            tmp.append(&mut x.to_be_bytes().to_vec());
        });
        cm_en.encrypt(&mut buf, tmp.as_slice()).unwrap();
        tmp.clear();
        ele.2.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        assert_eq!(tmp, buf, "encrypt-case: {}", i);

        let cm_de = cm.clone();
        tmp.clear();
        ele.2.iter().for_each(|&x| {
            tmp.append(&mut x.to_be_bytes().to_vec());
        });
        cm_de.decrypt(&mut buf, tmp.as_slice()).unwrap();
        tmp.clear();
        ele.1.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        assert_eq!(tmp, buf, "decrypt-case: {}", i);

        let (mut cm_encrypt, mut cm_decrypt) = (cm.clone().encrypt_stream(), cm.clone().decrypt_stream());
        
        ele.1.iter().for_each(|&x| {
            cm_encrypt.write(x.to_be_bytes().as_ref()).unwrap();
        });
        
        buf.clear();
        cm_encrypt.finish().unwrap().draw_off(&mut buf);
        
        tmp.clear();
        ele.2.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        
        assert_eq!(tmp, buf, "encrypt-case: {}", i);
        
        ele.2.iter().for_each(|&x| {
            cm_decrypt.write(x.to_be_bytes().as_ref()).unwrap();
        });
        
        buf.clear();
        cm_decrypt.finish().unwrap().draw_off(&mut buf);
        tmp.clear();
        ele.1.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        assert_eq!(tmp, buf, "decrypt-case: {}", i);
    }
}

#[test]
fn ctr_test() {
    let cases = [
        (
            (0x0123456789ABCDEFu64, 0x23456789ABCDEF01u64, 0x456789ABCDEF0123u64, 0xF69F2445DF4F9B17u64),
            vec![0x6BC1BEE2u32, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51,],
            vec![0x078BB74Eu32, 0x59CE7ED6, 0x19AA11D2, 0x5004FB65, 0xA03CEDF1, 0xBA0B09BA, 0xA3BC81B8, 0xF69C1DA9,],
        ),
        (
            (0x0123456789ABCDEFu64, 0x23456789ABCDEF01u64, 0x0123456789ABCDEFu64, 0xF69F2445DF4F9B17u64),
            vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51,],
            vec![0x6195B9C2, 0xC39909C5, 0xDBDF92DA, 0xDBAD5A5D, 0x1568482B, 0xF25C42C9, 0x6D3853A8, 0xE71B010E,],
        ),
   ];

    let (mut buf, mut tmp) = (Vec::with_capacity(16), Vec::with_capacity(16));
    for (i, ele) in cases.iter().enumerate() {
        let tdes = TDES::new(ele.0.0.to_be_bytes(), ele.0.1.to_be_bytes(), ele.0.2.to_be_bytes());
        buf.clear();
        buf.append(&mut ele.0.3.to_be_bytes().to_vec());
        let ctr = DefaultCounter::new(buf.clone(), tdes.block_size().unwrap() << 3).unwrap();
        let cm = CTR::new(tdes, ctr).unwrap();

        let cm_en = cm.clone();
        tmp.clear();
        ele.1.iter().for_each(|&x| {
            tmp.append(&mut x.to_be_bytes().to_vec());
        });
        cm_en.encrypt(&mut buf, tmp.as_slice()).unwrap();
        tmp.clear();
        ele.2.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        assert_eq!(tmp, buf, "encrypt-case: {}", i);
        
        let cm_de = cm.clone();
        tmp.clear();
        ele.2.iter().for_each(|&x| {
            tmp.append(&mut x.to_be_bytes().to_vec());
        });
        cm_de.decrypt(&mut buf, tmp.as_slice()).unwrap();
        tmp.clear();
        ele.1.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        assert_eq!(tmp, buf, "decrypt-case: {}", i);
        
        let (mut cm_encrypt, mut cm_decrypt) = (cm.clone().encrypt_stream(), cm.clone().decrypt_stream());
        
        ele.1.iter().for_each(|&x| {
            cm_encrypt.write(x.to_be_bytes().as_ref()).unwrap();
        });
        
        buf.clear();
        cm_encrypt.finish().unwrap().draw_off(&mut buf);
        
        tmp.clear();
        ele.2.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        
        assert_eq!(tmp, buf, "encrypt-case: {}", i);
        
        ele.2.iter().for_each(|&x| {
            cm_decrypt.write(x.to_be_bytes().as_ref()).unwrap();
        });
        
        buf.clear();
        cm_decrypt.finish().unwrap().draw_off(&mut buf);
        tmp.clear();
        ele.1.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        assert_eq!(tmp, buf, "decrypt-case: {}", i);
    }
}