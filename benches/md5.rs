//! # Bench Result
//!
//! ## Configurations  
//! 
//! Caption           : Intel64 Family 6 Model 158 Stepping 10  
//! DeviceID          : CPU0  
//! Manufacturer      : GenuineIntel  
//! MaxClockSpeed     : 2712  
//! Name              : Intel(R) Xeon(R) E-2176M  CPU @ 2.70GHz  
//! SocketDesignation : U3E1  
//! 
//! ## md5_generic
//! 
//! test md5 ... bench:       4,892 ns/iter (+/- 143)
//! 
//! ## md5_amd64
//! 
//! test md5 ... bench:       5,960 ns/iter (+/- 79)

#![feature(test)]

extern crate test;

use test::Bencher;
use rcrypto::{MD5, Digest};

#[bench]
fn md5(b: &mut Bencher) {
    let cases = [
        (0xd41d8cd98f00b204e9800998ecf8427eu128, ""),
        (0x0cc175b9c0f1b6a831c399e269772661u128, "a"),
        (0x187ef4436122d1cc2f40dc2b92f0eba0u128, "ab"),
        (0x900150983cd24fb0d6963f7d28e17f72u128, "abc"),
        (0xe2fc714c4727ee9395f324cd2e7f331fu128, "abcd"),
        (0xab56b4d92b40713acc5af89985d4b786u128, "abcde"),
        (0xe80b5017098950fc58aad83c8c14978eu128, "abcdef"),
        (0x7ac66c0f148de9519b8bd264312c4d64u128, "abcdefg"),
        (0xe8dc4081b13434b45189a720b77b6818u128, "abcdefgh"),
        (0x8aa99b1f439ff71293e95357bac6fd94u128, "abcdefghi"),
        (0xa925576942e94b2ef57a066101b48876u128, "abcdefghij"),
        (0xd747fc1719c7eacb84058196cfe56d57u128, "Discard medicine more than two years old."),
        (0xbff2dcb37ef3a44ba43ab144768ca837u128, "He who has a shady past knows that nice guys finish last."),
        (0x0441015ecb54a7342d017ed1bcfdbea5u128, "I wouldn't marry him with a ten foot pole."),
        (0x9e3cac8e9e9757a60c3ea391130d3689u128, "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"),
        (0xa0f04459b031f916a59a35cc482dc039u128, "The days of the digital watch are numbered.  -Tom Stoppard"),
        (0xe7a48e0fe884faf31475d2a04b1362ccu128, "Nepal premier won't resign."),
        (0x637d2fe925c07c113800509964fb0e06u128, "For every action there is an equal and opposite government program."),
        (0x834a8d18d5c6562119cf4c7f5086cb71u128, "His money is twice tainted: 'taint yours and 'taint mine."),
        (0xde3a4d2fd6c73ec2db2abad23b444281u128, "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"),
        (0xacf203f997e2cf74ea3aff86985aefafu128, "It's a tiny change to the code and not completely disgusting. - Bob Manchek"),
        (0xe1c1384cb4d2221dfdd7c795a4222c9au128, "size:  a.out:  bad magic"),
        (0xc90f3ddecc54f34228c063d7525bf644u128, "The major problem is with sendmail.  -Mark Horton"),
        (0xcdf7ab6c1fd49bd9933c43f3ea5af185u128, "Give me a rock, paper and scissors and I will move the world.  CCFestoon"),
        (0x83bc85234942fc883c063cbd7f0ad5d0u128, "If the enemy is within range, then so are you."),
        (0x277cbe255686b48dd7e8f389394d9299u128, "It's well we cannot hear the screams/That we create in others' dreams."),
        (0xfd3fb0a7ffb8af16603f3d3af98f8e1fu128, "You remind me of a TV show, but that's all right: I watch it anyway."),
        (0x469b13a78ebf297ecda64d4723655154u128, "C is as portable as Stonehedge!!"),
        (0x63eb3a2f466410104731c4b037600110u128, "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"),
        (0x72c2ed7592debca1c90fc0100f931a2fu128, "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"),
        (0x132f7619d33b523b1d9e5bd8e0928355u128, "How can you write a big system without C++?  -Paul Glick"),
    ];

    let mut md5 = MD5::new();
    let mut digest = Vec::with_capacity(md5.bits_len() >> 3);
    
    b.iter(|| {
        cases.iter().for_each(|e| {
            md5.write((e.1).as_bytes());
            md5.checksum(&mut digest);
            md5.reset();
        });
    });
}