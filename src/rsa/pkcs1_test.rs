use std::str::FromStr;
use rmath::bigint::BigInt;
use crate::rsa::{PrivateKey, PKCS1, KeyPair};
use rmath::rand::{DefaultSeed, CryptoRand};
use crate::{sha, Cipher, Signature};

fn pkcs1_get_private_key() -> PrivateKey {
    let n = BigInt::from_str("9353930466774385905609975137998169297361893554149986716853295022578535724979677252958524466350471210367835187480748268864277464700638583474144061408845077").unwrap();
    let e = BigInt::from(65537u32);
    let d = BigInt::from_str("7266398431328116344057699379749222532279343923819063639497049039389899328538543087657733766554155839834519529439851673014800261285757759040931985506583861").unwrap();
    let mut primes = Vec::with_capacity(2);
    
    primes.push(BigInt::from_str("98920366548084643601728869055592650835572950932266967461790948584315647051443").unwrap());
    primes.push(BigInt::from_str("94560208308847015747498523884063394671606671904944666360068158221458669711639").unwrap());
    
    PrivateKey::from_bigint_uncheck(&n, &e, &d, &primes).unwrap()
}

#[test]
fn pcks1_encrypt_decrypt() {
    // (ciphertext, decrypt_msg)
    let cases = [
        (vec![130u8, 39, 46, 138, 139, 228, 119, 166, 173, 153, 185, 63, 187, 249, 229, 115, 55, 28, 194, 185, 29, 145, 248, 220, 129, 247, 104, 223, 155, 233, 175, 25, 93, 186, 41, 49, 134, 124, 245, 198, 234, 101, 151, 59, 113, 107, 38, 222, 171, 94, 99, 185, 207, 158, 131, 46, 104, 209, 216, 111, 254, 123, 119, 202,], "x"),
        (vec![203u8, 187, 104, 114, 202, 168, 126, 8, 100, 173, 191, 163, 106, 250, 229, 206, 79, 49, 195, 103, 44, 163, 88, 175, 122, 205, 125, 186, 220, 239, 234, 28, 47, 199, 233, 188, 145, 251, 40, 194, 169, 185, 119, 54, 222, 141, 204, 237, 114, 247, 105, 146, 218, 90, 190, 235, 158, 110, 10, 124, 134, 123, 160, 119,], "testing."),
        (vec![106u8, 186, 222, 167, 215, 99, 181, 235, 242, 191, 103, 96, 221, 215, 105, 225, 207, 233, 178, 77, 104, 234, 92, 100, 162, 63, 33, 113, 251, 169, 162, 186, 43, 111, 56, 62, 239, 237, 95, 117, 172, 45, 214, 137, 103, 117, 215, 231, 170, 104, 230, 145, 191, 47, 199, 9, 167, 154, 139, 90, 183, 246, 223, 142,], "testing.\n"),
        (vec![194u8, 214, 155, 198, 42, 32, 115, 158, 62, 190, 29, 39, 135, 71, 33, 133, 239, 157, 173, 218, 44, 153, 207, 250, 110, 183, 223, 187, 105, 94, 169, 201, 37, 247, 235, 157, 187, 6, 159, 251, 24, 253, 154, 182, 234, 114, 56, 243, 114, 154, 174, 199, 189, 247, 207, 42, 36, 254, 59, 39, 169, 239, 223, 183,], "01234567890123456789012345678901234567890123456789012"),
    ];
    
    let pk = pkcs1_get_private_key();
    let (mut buf, mut dbuf) = (Vec::new(), Vec::new());
    let seed = DefaultSeed::<u32>::new().unwrap();
    let rd = CryptoRand::new(&seed).unwrap();
    let sha1 = sha::SHA1::new();

    let pkcs1 = PKCS1::new(sha1, rd, KeyPair::from(pk), false).unwrap();
    for (i, ele) in cases.iter().enumerate() {
        pkcs1.encrypt(&mut buf, ele.1.as_bytes()).unwrap();
        pkcs1.decrypt(&mut dbuf, buf.as_slice()).unwrap();
        assert_eq!(dbuf.as_slice(), ele.1.as_bytes(), "case: {}", i);
    }
}


#[test]
fn pkcs1_sign() {
    let cases = [
        ("Test.\n", vec![0xa4u8,0xf3,0xfa,0x6e,0xa9,0x3b,0xcd,0xd0,0xc5,0x7b,0xe0,0x20,0xc1,0x19,0x3e,0xcb,0xfd,0x6f,0x20,0x0a,0x3d,0x95,0xc4,0x09,0x76,0x9b,0x02,0x95,0x78,0xfa,0x0e,0x33,0x6a,0xd9,0xa3,0x47,0x60,0x0e,0x40,0xd3,0xae,0x82,0x3b,0x8c,0x7e,0x6b,0xad,0x88,0xcc,0x07,0xc1,0xd5,0x4c,0x3a,0x15,0x23,0xcb,0xbb,0x6d,0x58,0xef,0xc3,0x62,0xae,]),
    ];
    
    for (i, ele) in cases.iter().enumerate() {
        let pk = pkcs1_get_private_key();
        let mut buf = Vec::new();
        let seed = DefaultSeed::<u32>::new().unwrap();
        let rd = CryptoRand::new(&seed).unwrap();
        let sha1 = sha::SHA1::new();

        let mut pkcs1 = PKCS1::new(sha1, rd, KeyPair::from(pk), false).unwrap();
        pkcs1.sign(&mut buf, ele.0.as_bytes()).unwrap();
        assert_eq!(buf.as_slice(), ele.1.as_slice(), "case: {}", i);
        
        assert!(pkcs1.verify(buf.as_slice(), ele.0.as_bytes()).is_ok(), "case-verify: {}", i)
    }
}