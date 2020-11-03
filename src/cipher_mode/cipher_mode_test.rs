use crate::cipher_mode::{ECB, EmptyPadding, EncryptStream, DecryptStream, CBC, DefaultInitialVec};
use crate::{TDES, Cipher};
use rmath::rand::{CryptoRand, DefaultSeed};

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