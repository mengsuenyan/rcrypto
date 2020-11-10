use std::str::FromStr;
use crate::rsa::{PrivateKey, PSS, KeyPair, SignatureContent};
use crate::{sha, Signature};
use rmath::bigint::BigInt;
use rmath::rand::{DefaultSeed, CryptoRand};

fn emsa_get_private_key() -> PrivateKey {
    let n = BigInt::from_str("9353930466774385905609975137998169297361893554149986716853295022578535724979677252958524466350471210367835187480748268864277464700638583474144061408845077").unwrap();
    let e = BigInt::from(65537u32);
    let d = BigInt::from_str("7266398431328116344057699379749222532279343923819063639497049039389899328538543087657733766554155839834519529439851673014800261285757759040931985506583861").unwrap();
    let mut primes = Vec::with_capacity(2);

    primes.push(BigInt::from_str("98920366548084643601728869055592650835572950932266967461790948584315647051443").unwrap());
    primes.push(BigInt::from_str("94560208308847015747498523884063394671606671904944666360068158221458669711639").unwrap());

    PrivateKey::from_bigint_uncheck(&n, &e, &d, &primes).unwrap()
}

#[test]
fn emsa_pss() {
    let msg = vec![
        0x85u8, 0x9e, 0xef, 0x2f, 0xd7, 0x8a, 0xca, 0x00, 0x30, 0x8b,
        0xdc, 0x47, 0x11, 0x93, 0xbf, 0x55, 0xbf, 0x9d, 0x78, 0xdb,
        0x8f, 0x8a, 0x67, 0x2b, 0x48, 0x46, 0x34, 0xf3, 0xc9, 0xc2,
        0x6e, 0x64, 0x78, 0xae, 0x10, 0x26, 0x0f, 0xe0, 0xdd, 0x8c,
        0x08, 0x2e, 0x53, 0xa5, 0x29, 0x3a, 0xf2, 0x17, 0x3c, 0xd5,
        0x0c, 0x6d, 0x5d, 0x35, 0x4f, 0xeb, 0xf7, 0x8b, 0x26, 0x02,
        0x1c, 0x25, 0xc0, 0x27, 0x12, 0xe7, 0x8c, 0xd4, 0x69, 0x4c,
        0x9f, 0x46, 0x97, 0x77, 0xe4, 0x51, 0xe7, 0xf8, 0xe9, 0xe0,
        0x4c, 0xd3, 0x73, 0x9c, 0x6b, 0xbf, 0xed, 0xae, 0x48, 0x7f,
        0xb5, 0x56, 0x44, 0xe9, 0xca, 0x74, 0xff, 0x77, 0xa5, 0x3c,
        0xb7, 0x29, 0x80, 0x2f, 0x6e, 0xd4, 0xa5, 0xff, 0xa8, 0xba,
        0x15, 0x98, 0x90, 0xfc,
    ];
    let salt = vec![
        0xe3u8, 0xb5, 0xd5, 0xd0, 0x02, 0xc1, 0xbc, 0xe5, 0x0c, 0x2b,
        0x65, 0xef, 0x88, 0xa1, 0x88, 0xd8, 0x3b, 0xce, 0x7e, 0x61,
    ];
    let expected = vec![
        0x66u8, 0xe4, 0x67, 0x2e, 0x83, 0x6a, 0xd1, 0x21, 0xba, 0x24,
        0x4b, 0xed, 0x65, 0x76, 0xb8, 0x67, 0xd9, 0xa4, 0x47, 0xc2,
        0x8a, 0x6e, 0x66, 0xa5, 0xb8, 0x7d, 0xee, 0x7f, 0xbc, 0x7e,
        0x65, 0xaf, 0x50, 0x57, 0xf8, 0x6f, 0xae, 0x89, 0x84, 0xd9,
        0xba, 0x7f, 0x96, 0x9a, 0xd6, 0xfe, 0x02, 0xa4, 0xd7, 0x5f,
        0x74, 0x45, 0xfe, 0xfd, 0xd8, 0x5b, 0x6d, 0x3a, 0x47, 0x7c,
        0x28, 0xd2, 0x4b, 0xa1, 0xe3, 0x75, 0x6f, 0x79, 0x2d, 0xd1,
        0xdc, 0xe8, 0xca, 0x94, 0x44, 0x0e, 0xcb, 0x52, 0x79, 0xec,
        0xd3, 0x18, 0x3a, 0x31, 0x1f, 0xc8, 0x96, 0xda, 0x1c, 0xb3,
        0x93, 0x11, 0xaf, 0x37, 0xea, 0x4a, 0x75, 0xe2, 0x4b, 0xdb,
        0xfd, 0x5c, 0x1d, 0xa0, 0xde, 0x7c, 0xec, 0xdf, 0x1a, 0x89,
        0x6f, 0x9d, 0x8b, 0xc8, 0x16, 0xd9, 0x7c, 0xd7, 0xa2, 0xc4,
        0x3b, 0xad, 0x54, 0x6f, 0xbe, 0x8c, 0xfe, 0xbc,
    ];
    
    let sha1 = sha::SHA1::new();
    let seed = DefaultSeed::<u32>::new().unwrap();
    let rd = CryptoRand::new(&seed).unwrap();
    // let pk = emsa_get_private_key();
    // let mut emsa = PSS::new_uncheck(sha1, rd, KeyPair::from(pk), None, false).unwrap();
    let mut emsa = PSS::auto_generate_key(1024, 19, sha1, rd, Some(salt.len()), false).unwrap();
    
    let mut em = Vec::with_capacity(expected.len());
    emsa.emsa_pss_encode(&mut em, msg.as_slice(), 1023, salt.as_slice()).unwrap();
    
    assert_eq!(em, expected);
    emsa.emsa_pss_verify(em.as_slice(), msg.as_slice(), 1023).unwrap();
}

#[test]
fn emsa_pss_openssl() {
    let sig = vec![
        0x95u8, 0x59, 0x6f, 0xd3, 0x10, 0xa2, 0xe7, 0xa2, 0x92, 0x9d,
        0x4a, 0x07, 0x2e, 0x2b, 0x27, 0xcc, 0x06, 0xc2, 0x87, 0x2c,
        0x52, 0xf0, 0x4a, 0xcc, 0x05, 0x94, 0xf2, 0xc3, 0x2e, 0x20,
        0xd7, 0x3e, 0x66, 0x62, 0xb5, 0x95, 0x2b, 0xa3, 0x93, 0x9a,
        0x66, 0x64, 0x25, 0xe0, 0x74, 0x66, 0x8c, 0x3e, 0x92, 0xeb,
        0xc6, 0xe6, 0xc0, 0x44, 0xf3, 0xb4, 0xb4, 0x2e, 0x8c, 0x66,
        0x0a, 0x37, 0x9c, 0x69,
    ];
    let sha256 = sha::SHA256::new();
    let seed = DefaultSeed::<u32>::new().unwrap();
    let rd = CryptoRand::new(&seed).unwrap();
    let pk = emsa_get_private_key();
    let mut emsa = PSS::new_uncheck(sha256, rd, KeyPair::from(pk), Some(0), false).unwrap();
    let msg = "testing";
    let mut sign = SignatureContent::with_capacity(64);
    emsa.verify(&SignatureContent::from(sig), msg.as_bytes()).unwrap();
    emsa.sign(&mut sign, msg.as_bytes()).unwrap();
    emsa.verify(&sign, msg.as_bytes()).unwrap();
}