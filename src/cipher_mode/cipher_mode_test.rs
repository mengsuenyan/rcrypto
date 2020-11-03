use crate::cipher_mode::{ECB, EmptyPadding, EncryptStream, DecryptStream};
use crate::TDES;

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
        let ecb = ECB::new(tdes, EmptyPadding::new());
        let (mut ecb_encrypt, mut ecb_decrypt) = (ecb.clone().encrypt_stream(), ecb.decrypt_stream());
        
        ele.1.iter().for_each(|&x| {
            ecb_encrypt.write(x.to_be_bytes().as_ref()).unwrap();
        });
        
        buf.clear();
        ecb_encrypt.finish().unwrap().draw_off(&mut buf);
        
        tmp.clear();
        ele.2.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        
        assert_eq!(tmp, buf, "encrypt-case: {}", i);
        
        ele.2.iter().for_each(|&x| {
            ecb_decrypt.write(x.to_be_bytes().as_ref()).unwrap();
        });
        
        buf.clear();
        ecb_decrypt.finish().unwrap().draw_off(&mut buf);
        tmp.clear();
        ele.1.iter().for_each(|&x| {
            x.to_be_bytes().iter().for_each(|&y| {
                tmp.push(y);
            });
        });
        assert_eq!(tmp, buf, "decrypt-case: {}", i);
    }
}