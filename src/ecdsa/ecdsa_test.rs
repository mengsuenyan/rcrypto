use crate::elliptic::{CurveP224, CurveP256, CurveParams, EllipticCurve};
use crate::ecdsa::ECDSA;
use crate::sha::SHA1;
use rmath::rand::{DefaultSeed, CryptoRand};
use crate::dsa::SignatureContent;
use crate::Signature;

#[test]
fn ecdsa() {
    let hf = SHA1::new();
    let seed = DefaultSeed::<u32>::new().unwrap();
    let rd = CryptoRand::new(&seed).unwrap();
    let p224 = CurveP224::new().unwrap();
    let mut ecdsa0 = ECDSA::auto_generate_key(hf.clone(), rd.clone(), p224.clone()).unwrap();
    let p256 = CurveP256::new().unwrap();
    let mut ecdsa1 = ECDSA::auto_generate_key(hf.clone(), rd.clone(), p256.clone()).unwrap();
    let p384 = CurveParams::p384().unwrap();
    let mut ecdsa2 = ECDSA::auto_generate_key(hf.clone(), rd.clone(), p384.clone()).unwrap();
    let p521 = CurveParams::p521().unwrap();
    let mut ecdsa3 = ECDSA::auto_generate_key(hf.clone(), rd.clone(), p521.clone()).unwrap();
    
    assert!(p224.is_on_curve(&ecdsa0.public_key().qx, &ecdsa0. public_key().qy));
    assert!(p256.is_on_curve(&ecdsa1.public_key().qx, &ecdsa1. public_key().qy));
    assert!(p384.is_on_curve(&ecdsa2.public_key().qx, &ecdsa2. public_key().qy));
    assert!(p521.is_on_curve(&ecdsa3.public_key().qx, &ecdsa3. public_key().qy));
    
    let mut sig = SignatureContent::new();
    let s = "testing".as_bytes().to_vec();
    let mut ss = s.clone();
    ss.push(3);
    ecdsa0.sign(&mut sig, s.as_slice()).unwrap();
    ecdsa0.verify(&sig, s.as_slice()).unwrap();
    assert!(ecdsa0.verify(&sig, ss.as_slice()).is_err());
    ecdsa1.sign(&mut sig, s.as_slice()).unwrap();
    ecdsa1.verify(&sig, s.as_slice()).unwrap();
    assert!(ecdsa1.verify(&sig, ss.as_slice()).is_err());
    ecdsa2.sign(&mut sig, s.as_slice()).unwrap();
    ecdsa2.verify(&sig, s.as_slice()).unwrap();
    assert!(ecdsa2.verify(&sig, ss.as_slice()).is_err());
    ecdsa3.sign(&mut sig, s.as_slice()).unwrap();
    ecdsa3.verify(&sig, s.as_slice()).unwrap();
    assert!(ecdsa3.verify(&sig, ss.as_slice()).is_err());
}