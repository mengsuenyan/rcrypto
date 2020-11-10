use std::str::FromStr;
use crate::dsa::{DSA, SignatureContent, DomainParameters, PrivateKey, PublicKey, KeyPair};
use crate::{sha, Signature};
use rmath::rand::{DefaultSeed, CryptoRand};
use rmath::bigint::BigInt;

#[test]
fn dsa_parameter_generation() {
    let hf = sha::SHA1::new();
    let seed = DefaultSeed::<u32>::new().unwrap();
    let rd = CryptoRand::new(&seed).unwrap();
    
    let l1024n160 = DSA::new_with_l1024_n160(hf.clone(), rd.clone()).unwrap();
    let l2048n224 = DSA::new_with_l2048_n224(hf.clone(), rd.clone()).unwrap();
    let l2048n256 = DSA::new_with_l2048_n256(hf.clone(), rd.clone()).unwrap();
    let l3072n256 = DSA::new_with_l3072_n256(hf, rd).unwrap();
    
    let mut ln = [(l1024n160, 1024usize, 160usize), (l2048n224, 2048, 224), (l2048n256, 2048, 256), (l3072n256, 3072, 256)];
    
    for (dsa, l, n) in ln.iter_mut() {
        let (l, n) = (*l, *n);
        let (p, q, g) = dsa.key_pair().domain_parameters().unwrap();
        assert_eq!(p.bits_len(), l, "case-{}-{}", l, n);
        assert_eq!(q.bits_len(), n, "case-{}-{}", l, n);
        
        let one = BigInt::from(1u32);
        let pm1 = p.clone() - one.clone();
        let (quo, rem) = (pm1.div_euclid(q.clone()), pm1.rem_euclid(q.clone()));
        assert_eq!(rem.signnum(), Some(0), "case-{}-{}", l, n);
        let x = g.exp(&quo, &p);
        assert_ne!(x, one, "case-{}-{}", l, n);
        
        let msg = "testing";
        let mut sig = SignatureContent::new();
        let timestamp = std::time::Instant::now();
        dsa.sign(&mut sig, msg.as_bytes()).unwrap();
        dsa.verify(&sig, msg.as_bytes()).unwrap();
        println!("{:?}-case-{}-{}", timestamp.elapsed(), l, n);
    }
}

#[test]
fn dsa_sign_verify() {
    let dp = DomainParameters::new_uncheck(
        &BigInt::from_str("0xA9B5B793FB4785793D246BAE77E8FF63CA52F442DA763C440259919FE1BC1D6065A9350637A04F75A2F039401D49F08E066C4D275A5A65DA5684BC563C14289D7AB8A67163BFBF79D85972619AD2CFF55AB0EE77A9002B0EF96293BDD0F42685EBB2C66C327079F6C98000FBCB79AACDE1BC6F9D5C7B1A97E3D9D54ED7951FEF").unwrap(),
        &BigInt::from_str("0xE1D3391245933D68A0714ED34BBCB7A1F422B9C1").unwrap(),
        &BigInt::from_str("0x634364FC25248933D01D1993ECABD0657CC0CB2CEED7ED2E3E8AECDFCDC4A25C3B15E9E3B163ACA2984B5539181F3EFF1A5E8903D71D5B95DA4F27202B77D2C44B430BB53741A8D59A8F86887525C9F2A6A5980A195EAA7F2FF910064301DEF89D3AA213E1FAC7768D89365318E370AF54A112EFBA9246D9158386BA1B4EEFDA").unwrap()
    ).unwrap();
    let y = BigInt::from_str("0x32969E5780CFE1C849A1C276D7AEB4F38A23B591739AA2FE197349AEEBD31366AEE5EB7E6C6DDB7C57D02432B30DB5AA66D9884299FAA72568944E4EEDC92EA3FBC6F39F53412FBCC563208F7C15B737AC8910DBC2D9C9B8C001E72FDC40EB694AB1F06A5A2DBD18D9E36C66F31F566742F11EC0A52E9F7B89355C02FB5D32D2").unwrap();
    let x = BigInt::from_str("0x5078D4D29795CBE76D3AACFE48C9AF0BCDBEE91A").unwrap();
    
    let pk = PrivateKey::new_uncheck(
        &PublicKey::new_uncheck(&dp, &y).unwrap(),
        &x,
    ).unwrap();

    let hf = sha::SHA1::new();
    let seed = DefaultSeed::<u32>::new().unwrap();
    let rd = CryptoRand::new(&seed).unwrap();
    let mut dsa = DSA::new_uncheck(hf, rd, KeyPair::from(pk)).unwrap();
    let msg = "testing";
    let mut sig = SignatureContent::new();
    dsa.sign(&mut sig, msg.as_bytes()).unwrap();
    dsa.verify(&sig, msg.as_bytes()).unwrap();

    let dp = DomainParameters::new_uncheck(
        &BigInt::from_str("0xA9B5B793FB4785793D246BAE77E8FF63CA52F442DA763C440259919FE1BC1D6065A9350637A04F75A2F039401D49F08E066C4D275A5A65DA5684BC563C14289D7AB8A67163BFBF79D85972619AD2CFF55AB0EE77A9002B0EF96293BDD0F42685EBB2C66C327079F6C98000FBCB79AACDE1BC6F9D5C7B1A97E3D9D54ED7951FEF").unwrap(),
        &BigInt::from_str("0xFA").unwrap(),
        &BigInt::from_str("0x634364FC25248933D01D1993ECABD0657CC0CB2CEED7ED2E3E8AECDFCDC4A25C3B15E9E3B163ACA2984B5539181F3EFF1A5E8903D71D5B95DA4F27202B77D2C44B430BB53741A8D59A8F86887525C9F2A6A5980A195EAA7F2FF910064301DEF89D3AA213E1FAC7768D89365318E370AF54A112EFBA9246D9158386BA1B4EEFDA").unwrap()
    ).unwrap();
    let y = BigInt::from_str("0x32969E5780CFE1C849A1C276D7AEB4F38A23B591739AA2FE197349AEEBD31366AEE5EB7E6C6DDB7C57D02432B30DB5AA66D9884299FAA72568944E4EEDC92EA3FBC6F39F53412FBCC563208F7C15B737AC8910DBC2D9C9B8C001E72FDC40EB694AB1F06A5A2DBD18D9E36C66F31F566742F11EC0A52E9F7B89355C02FB5D32D2").unwrap();

    let pk = PublicKey::new_uncheck(&dp, &y).unwrap();
    let hf = sha::SHA1::new();
    let seed = DefaultSeed::<u32>::new().unwrap();
    let rd = CryptoRand::new(&seed).unwrap();
    let mut dsa = DSA::new_uncheck(hf, rd, KeyPair::from(pk)).unwrap();
    let mut sig = SignatureContent::new();
    sig.set(BigInt::from(2u32), BigInt::from(4u32));
    assert!(dsa.verify(&sig, msg.as_bytes()).is_err());
}