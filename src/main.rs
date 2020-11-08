use rmath::rand::{DefaultSeed, CryptoRand};
use rcrypto::rsa::PrivateKey;

fn main() {
    let size = 768;
    let seed = DefaultSeed::<u32>::new().unwrap();
    let mut rd = CryptoRand::new(&seed).unwrap();
    let _pk = PrivateKey::generate_multi_prime_key(3, size, 20, &mut rd).unwrap();

}