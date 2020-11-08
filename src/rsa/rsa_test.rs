use crate::rsa::PrivateKey;
use rmath::bigint::BigInt;
use rmath::rand::{CryptoRand, DefaultSeed};
use std::str::FromStr;

fn rsa_key_basics(pk: &PrivateKey, rd: &mut CryptoRand<u32>) {
    pk.is_valid().unwrap();
    
    assert!(pk.exponent() <= pk.modulus(), "private exponent too large");
    
    let m = BigInt::from(42u32);
    let c = pk.public_key().encrypt(&m);
    
    let m2 = pk.decrypt::<CryptoRand<u32>>(&c, None).unwrap();
    
    assert_eq!(m, m2, "encrypt message({}) does not equal to decrypt message({})", m, m2);
    
    let m3 = pk.decrypt(&c, Some(rd)).unwrap();
    
    assert_eq!(m, m3, "encrypt message({}) does not equal to decrypt message({}) with blinding", m, m2);
}

fn rsa_keygen(bits_len: usize, n_primes: usize) {
    let seed = DefaultSeed::<u32>::new().unwrap();
    let mut rd = CryptoRand::new(&seed).unwrap();
    let pk = PrivateKey::generate_multi_prime_key(n_primes, bits_len, 19, &mut rd).unwrap();

    assert_eq!(pk.modulus().bits_len(), bits_len, "The moudulus bits len is wrong");

    rsa_key_basics(&pk, &mut rd);
}

#[test]
fn rsa_keygen_1024() {
    let bits_len = 1024;
    rsa_keygen(bits_len, 2);
}

#[test]
fn rsa_multi3_prime_keygen() {
    let bits_len = 768;
    rsa_keygen(bits_len, 3);
}

#[test]
fn rsa_multi4_prime_keygen() {
    let bits_len = 768;
    rsa_keygen(bits_len, 4);
}

#[test]
fn rsa_multin_prime_keygen() {
    let (bits_len, max_n_primes) = (64, 24);
    
    for n in 5..max_n_primes {
        rsa_keygen(64+bits_len*n, n);
    }
}

#[test]
fn rsa_gnu_tls_key() {
    let n = BigInt::from_str("290684273230919398108010081414538931343").unwrap();
    let e = BigInt::from(65537u32); 
    let d = BigInt::from_str("31877380284581499213530787347443987241").unwrap();
    let mut primes = Vec::with_capacity(2);
    primes.push(BigInt::from_str("16775196964030542637").unwrap());
    primes.push(BigInt::from_str("17328218193455850539").unwrap());
    let pk = PrivateKey::from_bigint_uncheck(
        &n, &e, &d, &primes
    ).unwrap();

    let seed = DefaultSeed::<u32>::new().unwrap();
    let mut rd = CryptoRand::new(&seed).unwrap();
    rsa_key_basics(&pk, &mut rd);
}

#[test]
fn rsa_keygen_2048() {
    let bits_len = 2048;
    rsa_keygen(bits_len, 2);
    
    let n = BigInt::from_str("14314132931241006650998084889274020608918049032671858325988396851334124245188214251956198731333464217832226406088020736932173064754214329009979944037640912127943488972644697423190955557435910767690712778463524983667852819010259499695177313115447116110358524558307947613422897787329221478860907963827160223559690523660574329011927531289655711860504630573766609239332569210831325633840174683944553667352219670930408593321661375473885147973879086994006440025257225431977751512374815915392249179976902953721486040787792801849818254465486633791826766873076617116727073077821584676715609985777563958286637185868165868520557").unwrap();
    let e = BigInt::from(3u32);
    let d = BigInt::from_str("9542755287494004433998723259516013739278699355114572217325597900889416163458809501304132487555642811888150937392013824621448709836142886006653296025093941418628992648429798282127303704957273845127141852309016655778568546006839666463451542076964744073572349705538631742281931858219480985907271975884773482372966847639853897890615456605598071088189838676728836833012254065983259638538107719766738032720239892094196108713378822882383694456030043492571063441943847195939549773271694647657549658603365629458610273821292232646334717612674519997533901052790334279661754176490593041941863932308687197618671528035670452762731").unwrap();
    let mut primes = Vec::with_capacity(2);
    primes.push(BigInt::from_str("130903255182996722426771613606077755295583329135067340152947172868415809027537376306193179624298874215608270802054347609836776473930072411958753044562214537013874103802006369634761074377213995983876788718033850153719421695468704276694983032644416930879093914927146648402139231293035971427838068945045019075433").unwrap());
    primes.push(BigInt::from_str("109348945610485453577574767652527472924289229538286649661240938988020367005475727988253438647560958573506159449538793540472829815903949343191091817779240101054552748665267574271163617694640513549693841337820602726596756351006149518830932261246698766355347898158548465400674856021497190430791824869615170301029").unwrap());
    let pk = PrivateKey::from_bigint_uncheck(
        &n, &e, &d, &primes
    ).unwrap();

    let seed = DefaultSeed::<u32>::new().unwrap();
    let mut rd = CryptoRand::new(&seed).unwrap();
    rsa_key_basics(&pk, &mut rd);
}
