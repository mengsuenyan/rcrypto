#![feature(test)]

extern crate test;

use test::Bencher;
use rcrypto::{SM3, Digest};

#[bench]
fn sm3(b: &mut Bencher) {
    let cases = [
        ("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", "abc"),
        ("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732","abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"),
    ];

    let mut sm3 = SM3::new();
    let mut digest = Vec::new();
    b.iter(|| {
        cases.iter().for_each(|&e| {
            sm3.write(e.1.as_bytes());
            sm3.checksum(&mut digest);
            sm3.checksum(&mut digest);
            sm3.reset();
        });
    });
}