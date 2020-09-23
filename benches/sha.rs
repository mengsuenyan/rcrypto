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
//! ## sha_generic
//! test sha1       ... bench:       9,102 ns/iter (+/- 348)
//! test sha224     ... bench:      14,499 ns/iter (+/- 728)
//! test sha256     ... bench:      14,318 ns/iter (+/- 535)
//! test sha512     ... bench:      13,750 ns/iter (+/- 610)
//! test sha512t224 ... bench:      14,023 ns/iter (+/- 1,721)
//! test sha512t256 ... bench:      13,821 ns/iter (+/- 347)
//! test sha512t384 ... bench:      13,958 ns/iter (+/- 1,219)
//! 
//! ## sha_amd64
//! 
#![feature(test)]

extern crate test;

use test::Bencher;
use rcrypto::{SHA, Digest};

#[bench]
fn sha1(b:  &mut Bencher) {
    let cases = [
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", ""),
        ("86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", "a"),
        ("da23614e02469a0d7c7bd1bdab5c9c474b1904dc", "ab"),
        ("a9993e364706816aba3e25717850c26c9cd0d89d", "abc"),
        ("81fe8bfe87576c3ecb22426f8e57847382917acf", "abcd"),
        ("03de6c570bfe24bfc328ccd7ca46b76eadaf4334", "abcde"),
        ("1f8ac10f23c5b5bc1167bda84b833e5c057a77d2", "abcdef"),
        ("2fb5e13419fc89246865e7a324f476ec624e8740", "abcdefg"),
        ("425af12a0743502b322e93a015bcf868e324d56a", "abcdefgh"),
        ("c63b19f1e4c8b5f76b25c49b8b87f57d8e4872a1", "abcdefghi"),
        ("d68c19a0a345b7eab78d5e11e991c026ec60db63", "abcdefghij"),
        ("ebf81ddcbe5bf13aaabdc4d65354fdf2044f38a7", "Discard medicine more than two years old."),
        ("e5dea09392dd886ca63531aaa00571dc07554bb6", "He who has a shady past knows that nice guys finish last."),
        ("45988f7234467b94e3e9494434c96ee3609d8f8f", "I wouldn't marry him with a ten foot pole."),
        ("55dee037eb7460d5a692d1ce11330b260e40c988", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"),
        ("b7bc5fb91080c7de6b582ea281f8a396d7c0aee8", "The days of the digital watch are numbered.  -Tom Stoppard"),
        ("c3aed9358f7c77f523afe86135f06b95b3999797", "Nepal premier won't resign."),
        ("6e29d302bf6e3a5e4305ff318d983197d6906bb9", "For every action there is an equal and opposite government program."),
        ("597f6a540010f94c15d71806a99a2c8710e747bd", "His money is twice tainted: 'taint yours and 'taint mine."),
        ("6859733b2590a8a091cecf50086febc5ceef1e80", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"),
        ("514b2630ec089b8aee18795fc0cf1f4860cdacad", "It's a tiny change to the code and not completely disgusting. - Bob Manchek"),
        ("c5ca0d4a7b6676fc7aa72caa41cc3d5df567ed69", "size:  a.out:  bad magic"),
        ("74c51fa9a04eadc8c1bbeaa7fc442f834b90a00a", "The major problem is with sendmail.  -Mark Horton"),
        ("0b4c4ce5f52c3ad2821852a8dc00217fa18b8b66", "Give me a rock, paper and scissors and I will move the world.  CCFestoon"),
        ("3ae7937dd790315beb0f48330e8642237c61550a", "If the enemy is within range, then so are you."),
        ("410a2b296df92b9a47412b13281df8f830a9f44b", "It's well we cannot hear the screams/That we create in others' dreams."),
        ("841e7c85ca1adcddbdd0187f1289acb5c642f7f5", "You remind me of a TV show, but that's all right: I watch it anyway."),
        ("163173b825d03b952601376b25212df66763e1db", "C is as portable as Stonehedge!!"),
        ("32b0377f2687eb88e22106f133c586ab314d5279", "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"),
        ("0885aaf99b569542fd165fa44e322718f4a984e0", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"),
        ("6627d6904d71420b0bf3886ab629623538689f45", "How can you write a big system without C++?  -Paul Glick"),
        ("76245dbf96f661bd221046197ab8b9f063f11bad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"),
    ];

    let mut sha1 = SHA::sha1();
    let mut digest = Vec::new();
    b.iter(|| {
        cases.iter().for_each(|e| {
            sha1.write((e.1).as_bytes());
            sha1.checksum(&mut digest);
            sha1.checksum(&mut digest);
            sha1.reset();
        });
    });
}

#[bench]
fn sha256(b: &mut Bencher) {
    let cases = [
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ""),
        ("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "a"),
        ("fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603", "ab"),
        ("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc"),
        ("88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589", "abcd"),
        ("36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c", "abcde"),
        ("bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721", "abcdef"),
        ("7d1a54127b222502f5b79b5fb0803061152a44f92b37e23c6527baf665d4da9a", "abcdefg"),
        ("9c56cc51b374c3ba189210d5b6d4bf57790d351c96c47c02190ecf1e430635ab", "abcdefgh"),
        ("19cc02f26df43cc571bc9ed7b0c4d29224a3ec229529221725ef76d021c8326f", "abcdefghi"),
        ("72399361da6a7754fec986dca5b7cbaf1c810a28ded4abaf56b2106d06cb78b0", "abcdefghij"),
        ("a144061c271f152da4d151034508fed1c138b8c976339de229c3bb6d4bbb4fce", "Discard medicine more than two years old."),
        ("6dae5caa713a10ad04b46028bf6dad68837c581616a1589a265a11288d4bb5c4", "He who has a shady past knows that nice guys finish last."),
        ("ae7a702a9509039ddbf29f0765e70d0001177914b86459284dab8b348c2dce3f", "I wouldn't marry him with a ten foot pole."),
        ("6748450b01c568586715291dfa3ee018da07d36bb7ea6f180c1af6270215c64f", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"),
        ("14b82014ad2b11f661b5ae6a99b75105c2ffac278cd071cd6c05832793635774", "The days of the digital watch are numbered.  -Tom Stoppard"),
        ("7102cfd76e2e324889eece5d6c41921b1e142a4ac5a2692be78803097f6a48d8", "Nepal premier won't resign."),
        ("23b1018cd81db1d67983c5f7417c44da9deb582459e378d7a068552ea649dc9f", "For every action there is an equal and opposite government program."),
        ("8001f190dfb527261c4cfcab70c98e8097a7a1922129bc4096950e57c7999a5a", "His money is twice tainted: 'taint yours and 'taint mine."),
        ("8c87deb65505c3993eb24b7a150c4155e82eee6960cf0c3a8114ff736d69cad5", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"),
        ("bfb0a67a19cdec3646498b2e0f751bddc41bba4b7f30081b0b932aad214d16d7", "It's a tiny change to the code and not completely disgusting. - Bob Manchek"),
        ("7f9a0b9bf56332e19f5a0ec1ad9c1425a153da1c624868fda44561d6b74daf36", "size:  a.out:  bad magic"),
        ("b13f81b8aad9e3666879af19886140904f7f429ef083286195982a7588858cfc", "The major problem is with sendmail.  -Mark Horton"),
        ("b26c38d61519e894480c70c8374ea35aa0ad05b2ae3d6674eec5f52a69305ed4", "Give me a rock, paper and scissors and I will move the world.  CCFestoon"),
        ("049d5e26d4f10222cd841a119e38bd8d2e0d1129728688449575d4ff42b842c1", "If the enemy is within range, then so are you."),
        ("0e116838e3cc1c1a14cd045397e29b4d087aa11b0853fc69ec82e90330d60949", "It's well we cannot hear the screams/That we create in others' dreams."),
        ("4f7d8eb5bcf11de2a56b971021a444aa4eafd6ecd0f307b5109e4e776cd0fe46", "You remind me of a TV show, but that's all right: I watch it anyway."),
        ("61c0cc4c4bd8406d5120b3fb4ebc31ce87667c162f29468b3c779675a85aebce", "C is as portable as Stonehedge!!"),
        ("1fb2eb3688093c4a3f80cd87a5547e2ce940a4f923243a79a2a1e242220693ac", "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"),
        ("395585ce30617b62c80b93e8208ce866d4edc811a177fdb4b82d3911d8696423", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"),
        ("4f9b189a13d030838269dce846b16a1ce9ce81fe63e65de2f636863336a98fe6", "How can you write a big system without C++?  -Paul Glick"),
    ];

    let mut sha = SHA::sha256();
    let mut digest = Vec::new();
    b.iter(|| {
        cases.iter().for_each(|e| {
            sha.write((e.1).as_bytes());
            sha.checksum(&mut digest);
            sha.checksum(&mut digest);
            sha.reset();
        });
       
    });
}

#[bench]
fn sha224(b: &mut Bencher) {
    let cases = [
        ("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", ""),
        ("abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5", "a"),
        ("db3cda86d4429a1d39c148989566b38f7bda0156296bd364ba2f878b", "ab"),
        ("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", "abc"),
        ("a76654d8e3550e9a2d67a0eeb6c67b220e5885eddd3fde135806e601", "abcd"),
        ("bdd03d560993e675516ba5a50638b6531ac2ac3d5847c61916cfced6", "abcde"),
        ("7043631cb415556a275a4ebecb802c74ee9f6153908e1792a90b6a98", "abcdef"),
        ("d1884e711701ad81abe0c77a3b0ea12e19ba9af64077286c72fc602d", "abcdefg"),
        ("17eb7d40f0356f8598e89eafad5f6c759b1f822975d9c9b737c8a517", "abcdefgh"),
        ("aeb35915346c584db820d2de7af3929ffafef9222a9bcb26516c7334", "abcdefghi"),
        ("d35e1e5af29ddb0d7e154357df4ad9842afee527c689ee547f753188", "abcdefghij"),
        ("19297f1cef7ddc8a7e947f5c5a341e10f7245045e425db67043988d7", "Discard medicine more than two years old."),
        ("0f10c2eb436251f777fbbd125e260d36aecf180411726c7c885f599a", "He who has a shady past knows that nice guys finish last."),
        ("4d1842104919f314cad8a3cd20b3cba7e8ed3e7abed62b57441358f6", "I wouldn't marry him with a ten foot pole."),
        ("a8ba85c6fe0c48fbffc72bbb2f03fcdbc87ae2dc7a56804d1590fb3b", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"),
        ("5543fbab26e67e8885b1a852d567d1cb8b9bfe42e0899584c50449a9", "The days of the digital watch are numbered.  -Tom Stoppard"),
        ("65ca107390f5da9efa05d28e57b221657edc7e43a9a18fb15b053ddb", "Nepal premier won't resign."),
        ("84953962be366305a9cc9b5cd16ed019edc37ac96c0deb3e12cca116", "For every action there is an equal and opposite government program."),
        ("35a189ce987151dfd00b3577583cc6a74b9869eecf894459cb52038d", "His money is twice tainted: 'taint yours and 'taint mine."),
        ("2fc333713983edfd4ef2c0da6fb6d6415afb94987c91e4069eb063e6", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"),
        ("cbe32d38d577a1b355960a4bc3c659c2dc4670859a19777a875842c4", "It's a tiny change to the code and not completely disgusting. - Bob Manchek"),
        ("a2dc118ce959e027576413a7b440c875cdc8d40df9141d6ef78a57e1", "size:  a.out:  bad magic"),
        ("d10787e24052bcff26dc484787a54ed819e4e4511c54890ee977bf81", "The major problem is with sendmail.  -Mark Horton"),
        ("62efcf16ab8a893acdf2f348aaf06b63039ff1bf55508c830532c9fb", "Give me a rock, paper and scissors and I will move the world.  CCFestoon"),
        ("3e9b7e4613c59f58665104c5fa86c272db5d3a2ff30df5bb194a5c99", "If the enemy is within range, then so are you."),
        ("5999c208b8bdf6d471bb7c359ac5b829e73a8211dff686143a4e7f18", "It's well we cannot hear the screams/That we create in others' dreams."),
        ("3b2d67ff54eabc4ef737b14edf87c64280ef582bcdf2a6d56908b405", "You remind me of a TV show, but that's all right: I watch it anyway."),
        ("d0733595d20e4d3d6b5c565a445814d1bbb2fd08b9a3b8ffb97930c6", "C is as portable as Stonehedge!!"),
        ("43fb8aeed8a833175c9295c1165415f98c866ef08a4922959d673507", "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"),
        ("ec18e66e93afc4fb1604bc2baedbfd20b44c43d76e65c0996d7851c6", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"),
        ("86ed2eaa9c75ba98396e5c9fb2f679ecf0ea2ed1e0ee9ceecb4a9332", "How can you write a big system without C++?  -Paul Glick"),
    ];

    let mut sha = SHA::sha224();
    let mut digest = Vec::new();
    b.iter(|| {
        cases.iter().for_each(|e| {
            sha.write((e.1).as_bytes());
            sha.checksum(&mut digest);

            sha.checksum(&mut digest);
            sha.reset();
        });
    });
}

#[bench]
fn sha512(b: &mut Bencher) {
    let cases = [
        (
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            "",
        ),
        (
            "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
            "a",
        ),
        (
            "2d408a0717ec188158278a796c689044361dc6fdde28d6f04973b80896e1823975cdbf12eb63f9e0591328ee235d80e9b5bf1aa6a44f4617ff3caf6400eb172d",
            "ab",
        ),
        (
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "abc",
        ),
        (
            "d8022f2060ad6efd297ab73dcc5355c9b214054b0d1776a136a669d26a7d3b14f73aa0d0ebff19ee333368f0164b6419a96da49e3e481753e7e96b716bdccb6f",
            "abcd",
        ),
        (
            "878ae65a92e86cac011a570d4c30a7eaec442b85ce8eca0c2952b5e3cc0628c2e79d889ad4d5c7c626986d452dd86374b6ffaa7cd8b67665bef2289a5c70b0a1",
            "abcde",
        ),
        (
            "e32ef19623e8ed9d267f657a81944b3d07adbb768518068e88435745564e8d4150a0a703be2a7d88b61e3d390c2bb97e2d4c311fdc69d6b1267f05f59aa920e7",
            "abcdef",
        ),
        (
            "d716a4188569b68ab1b6dfac178e570114cdf0ea3a1cc0e31486c3e41241bc6a76424e8c37ab26f096fc85ef9886c8cb634187f4fddff645fb099f1ff54c6b8c",
            "abcdefg",
        ),
        (
            "a3a8c81bc97c2560010d7389bc88aac974a104e0e2381220c6e084c4dccd1d2d17d4f86db31c2a851dc80e6681d74733c55dcd03dd96f6062cdda12a291ae6ce",
            "abcdefgh",
        ),
        (
            "f22d51d25292ca1d0f68f69aedc7897019308cc9db46efb75a03dd494fc7f126c010e8ade6a00a0c1a5f1b75d81e0ed5a93ce98dc9b833db7839247b1d9c24fe",
            "abcdefghi",
        ),
        (
            "ef6b97321f34b1fea2169a7db9e1960b471aa13302a988087357c520be957ca119c3ba68e6b4982c019ec89de3865ccf6a3cda1fe11e59f98d99f1502c8b9745",
            "abcdefghij",
        ),
        (
            "2210d99af9c8bdecda1b4beff822136753d8342505ddce37f1314e2cdbb488c6016bdaa9bd2ffa513dd5de2e4b50f031393d8ab61f773b0e0130d7381e0f8a1d",
            "Discard medicine more than two years old.",
        ),
        (
            "a687a8985b4d8d0a24f115fe272255c6afaf3909225838546159c1ed685c211a203796ae8ecc4c81a5b6315919b3a64f10713da07e341fcdbb08541bf03066ce",
            "He who has a shady past knows that nice guys finish last.",
        ),
        (
            "8ddb0392e818b7d585ab22769a50df660d9f6d559cca3afc5691b8ca91b8451374e42bcdabd64589ed7c91d85f626596228a5c8572677eb98bc6b624befb7af8",
            "I wouldn't marry him with a ten foot pole.",
        ),
        (
            "26ed8f6ca7f8d44b6a8a54ae39640fa8ad5c673f70ee9ce074ba4ef0d483eea00bab2f61d8695d6b34df9c6c48ae36246362200ed820448bdc03a720366a87c6",
            "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave",
        ),
        (
            "e5a14bf044be69615aade89afcf1ab0389d5fc302a884d403579d1386a2400c089b0dbb387ed0f463f9ee342f8244d5a38cfbc0e819da9529fbff78368c9a982",
            "The days of the digital watch are numbered.  -Tom Stoppard",
        ),
        (
            "420a1faa48919e14651bed45725abe0f7a58e0f099424c4e5a49194946e38b46c1f8034b18ef169b2e31050d1648e0b982386595f7df47da4b6fd18e55333015",
            "Nepal premier won't resign.",
        ),
        (
            "d926a863beadb20134db07683535c72007b0e695045876254f341ddcccde132a908c5af57baa6a6a9c63e6649bba0c213dc05fadcf9abccea09f23dcfb637fbe",
            "For every action there is an equal and opposite government program.",
        ),
        (
            "9a98dd9bb67d0da7bf83da5313dff4fd60a4bac0094f1b05633690ffa7f6d61de9a1d4f8617937d560833a9aaa9ccafe3fd24db418d0e728833545cadd3ad92d",
            "His money is twice tainted: 'taint yours and 'taint mine.",
        ),
        (
            "d7fde2d2351efade52f4211d3746a0780a26eec3df9b2ed575368a8a1c09ec452402293a8ea4eceb5a4f60064ea29b13cdd86918cd7a4faf366160b009804107",
            "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977",
        ),
        (
            "b0f35ffa2697359c33a56f5c0cf715c7aeed96da9905ca2698acadb08fbc9e669bf566b6bd5d61a3e86dc22999bcc9f2224e33d1d4f32a228cf9d0349e2db518",
            "It's a tiny change to the code and not completely disgusting. - Bob Manchek",
        ),
        (
            "3d2e5f91778c9e66f7e061293aaa8a8fc742dd3b2e4f483772464b1144189b49273e610e5cccd7a81a19ca1fa70f16b10f1a100a4d8c1372336be8484c64b311",
            "size:  a.out:  bad magic",
        ),
        (
            "b2f68ff58ac015efb1c94c908b0d8c2bf06f491e4de8e6302c49016f7f8a33eac3e959856c7fddbc464de618701338a4b46f76dbfaf9a1e5262b5f40639771c7",
            "The major problem is with sendmail.  -Mark Horton",
        ),
        (
            "d8c92db5fdf52cf8215e4df3b4909d29203ff4d00e9ad0b64a6a4e04dec5e74f62e7c35c7fb881bd5de95442123df8f57a489b0ae616bd326f84d10021121c57",
            "Give me a rock, paper and scissors and I will move the world.  CCFestoon",
        ),
        (
            "19a9f8dc0a233e464e8566ad3ca9b91e459a7b8c4780985b015776e1bf239a19bc233d0556343e2b0a9bc220900b4ebf4f8bdf89ff8efeaf79602d6849e6f72e",
            "If the enemy is within range, then so are you.",
        ),
        (
            "00b4c41f307bde87301cdc5b5ab1ae9a592e8ecbb2021dd7bc4b34e2ace60741cc362560bec566ba35178595a91932b8d5357e2c9cec92d393b0fa7831852476",
            "It's well we cannot hear the screams/That we create in others' dreams.",
        ),
        (
            "91eccc3d5375fd026e4d6787874b1dce201cecd8a27dbded5065728cb2d09c58a3d467bb1faf353bf7ba567e005245d5321b55bc344f7c07b91cb6f26c959be7",
            "You remind me of a TV show, but that's all right: I watch it anyway.",
        ),
        (
            "fabbbe22180f1f137cfdc9556d2570e775d1ae02a597ded43a72a40f9b485d500043b7be128fb9fcd982b83159a0d99aa855a9e7cc4240c00dc01a9bdf8218d7",
            "C is as portable as Stonehedge!!",
        ),
        (
            "2ecdec235c1fa4fc2a154d8fba1dddb8a72a1ad73838b51d792331d143f8b96a9f6fcb0f34d7caa351fe6d88771c4f105040e0392f06e0621689d33b2f3ba92e",
            "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley",
        ),
        (
            "7ad681f6f96f82f7abfa7ecc0334e8fa16d3dc1cdc45b60b7af43fe4075d2357c0c1d60e98350f1afb1f2fe7a4d7cd2ad55b88e458e06b73c40b437331f5dab4",
            "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule",
        ),
        (
            "833f9248ab4a3b9e5131f745fda1ffd2dd435b30e965957e78291c7ab73605fd1912b0794e5c233ab0a12d205a39778d19b83515d6a47003f19cdee51d98c7e0",
            "How can you write a big system without C++?  -Paul Glick",
        ),
    ];

    let mut sha = SHA::sha512();
    let mut digest = Vec::new();
    b.iter(|| {
        cases.iter().for_each(|e| {
            sha.write((e.1).as_bytes());
            sha.checksum(&mut digest);

            sha.checksum(&mut digest);

            sha.reset();
        });
    });
}

#[bench]
fn sha512t384(b: &mut Bencher) {
    let cases = [
        (
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            "",
        ),
        (
            "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
            "a",
        ),
        (
            "c7be03ba5bcaa384727076db0018e99248e1a6e8bd1b9ef58a9ec9dd4eeebb3f48b836201221175befa74ddc3d35afdd",
            "ab",
        ),
        (
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            "abc",
        ),
        (
            "1165b3406ff0b52a3d24721f785462ca2276c9f454a116c2b2ba20171a7905ea5a026682eb659c4d5f115c363aa3c79b",
            "abcd",
        ),
        (
            "4c525cbeac729eaf4b4665815bc5db0c84fe6300068a727cf74e2813521565abc0ec57a37ee4d8be89d097c0d2ad52f0",
            "abcde",
        ),
        (
            "c6a4c65b227e7387b9c3e839d44869c4cfca3ef583dea64117859b808c1e3d8ae689e1e314eeef52a6ffe22681aa11f5",
            "abcdef",
        ),
        (
            "9f11fc131123f844c1226f429b6a0a6af0525d9f40f056c7fc16cdf1b06bda08e302554417a59fa7dcf6247421959d22",
            "abcdefg",
        ),
        (
            "9000cd7cada59d1d2eb82912f7f24e5e69cc5517f68283b005fa27c285b61e05edf1ad1a8a9bded6fd29eb87d75ad806",
            "abcdefgh",
        ),
        (
            "ef54915b60cf062b8dd0c29ae3cad69abe6310de63ac081f46ef019c5c90897caefd79b796cfa81139788a260ded52df",
            "abcdefghi",
        ),
        (
            "a12070030a02d86b0ddacd0d3a5b598344513d0a051e7355053e556a0055489c1555399b03342845c4adde2dc44ff66c",
            "abcdefghij",
        ),
        (
            "86f58ec2d74d1b7f8eb0c2ff0967316699639e8d4eb129de54bdf34c96cdbabe200d052149f2dd787f43571ba74670d4",
            "Discard medicine more than two years old.",
        ),
        (
            "ae4a2b639ca9bfa04b1855d5a05fe7f230994f790891c6979103e2605f660c4c1262a48142dcbeb57a1914ba5f7c3fa7",
            "He who has a shady past knows that nice guys finish last.",
        ),
        (
            "40ae213df6436eca952aa6841886fcdb82908ef1576a99c8f49bb9dd5023169f7c53035abdda0b54c302f4974e2105e7",
            "I wouldn't marry him with a ten foot pole.",
        ),
        (
            "e7cf8b873c9bc950f06259aa54309f349cefa72c00d597aebf903e6519a50011dfe355afff064a10701c705693848df9",
            "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave",
        ),
        (
            "c3d4f0f4047181c7d39d34703365f7bf70207183caf2c2f6145f04da895ef69124d9cdeb635da636c3a474e61024e29b",
            "The days of the digital watch are numbered.  -Tom Stoppard",
        ),
        (
            "a097aab567e167d5cf93676ed73252a69f9687cb3179bb2d27c9878119e94bf7b7c4b58dc90582edfaf66e11388ed714",
            "Nepal premier won't resign.",
        ),
        (
            "5026ca45c41fc64712eb65065da92f6467541c78f8966d3fe2c8e3fb769a3ec14215f819654b47bd64f7f0eac17184f3",
            "For every action there is an equal and opposite government program.",
        ),
        (
            "ac1cc0f5ac8d5f5514a7b738ac322b7fb52a161b449c3672e9b6a6ad1a5e4b26b001cf3bad24c56598676ca17d4b445a",
            "His money is twice tainted: 'taint yours and 'taint mine.",
        ),
        (
            "722d10c5de371ec0c8c4b5247ac8a5f1d240d68c73f8da13d8b25f0166d6f309bf9561979a111a0049405771d201941a",
            "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977",
        ),
        (
            "dc2d3ea18bfa10549c63bf2b75b39b5167a80c12aff0e05443168ea87ff149fb0eda5e0bd234eb5d48c7d02ffc5807f1",
            "It's a tiny change to the code and not completely disgusting. - Bob Manchek",
        ),
        (
            "1d67c969e2a945ae5346d2139760261504d4ba164c522443afe19ef3e29b152a4c52445489cfc9d7215e5a450e8e1e4e",
            "size:  a.out:  bad magic",
        ),
        (
            "5ff8e075e465646e7b73ef36d812c6e9f7d60fa6ea0e533e5569b4f73cde53cdd2cc787f33540af57cca3fe467d32fe0",
            "The major problem is with sendmail.  -Mark Horton",
        ),
        (
            "5bd0a997a67c9ae1979a894eb0cde403dde003c9b6f2c03cf21925c42ff4e1176e6df1ca005381612ef18457b9b7ec3b",
            "Give me a rock, paper and scissors and I will move the world.  CCFestoon",
        ),
        (
            "1eee6da33e7e54fc5be52ae23b94b16ba4d2a947ae4505c6a3edfc7401151ea5205ac01b669b56f27d8ef7f175ed7762",
            "If the enemy is within range, then so are you.",
        ),
        (
            "76b06e9dea66bfbb1a96029426dc0dfd7830bd297eb447ff5358d94a87cd00c88b59df2493fef56ecbb5231073892ea9",
            "It's well we cannot hear the screams/That we create in others' dreams.",
        ),
        (
            "12acaf21452cff586143e3f5db0bfdf7802c057e1adf2a619031c4e1b0ccc4208cf6cef8fe722bbaa2fb46a30d9135d8",
            "You remind me of a TV show, but that's all right: I watch it anyway.",
        ),
        (
            "0fc23d7f4183efd186f0bc4fc5db867e026e2146b06cb3d52f4bdbd57d1740122caa853b41868b197b2ac759db39df88",
            "C is as portable as Stonehedge!!",
        ),
        (
            "bc805578a7f85d34a86a32976e1c34fe65cf815186fbef76f46ef99cda10723f971f3f1464d488243f5e29db7488598d",
            "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley",
        ),
        (
            "b23918399a12ebf4431559eec3813eaf7412e875fd7464f16d581e473330842d2e96c6be49a7ce3f9bb0b8bc0fcbe0fe",
            "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule",
        ),
        (
            "1764b700eb1ead52a2fc33cc28975c2180f1b8faa5038d94cffa8d78154aab16e91dd787e7b0303948ebed62561542c8",
            "How can you write a big system without C++?  -Paul Glick",
        ),
    ];

    let mut sha = SHA::sha384();
    let mut digest = Vec::new();
    b.iter(|| {
        cases.iter().for_each(|e| {
            sha.write((e.1).as_bytes());
            sha.checksum(&mut digest);

            sha.checksum(&mut digest);
            sha.reset();
        });
    });
}

#[bench]
fn sha512t224(b: &mut Bencher) {
    let cases = [
        (
            "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
            "",
        ),
        (
            "d5cdb9ccc769a5121d4175f2bfdd13d6310e0d3d361ea75d82108327",
            "a",
        ),
        (
            "b35878d07bfedf39fc638af08547eb5d1072d8546319f247b442fbf5",
            "ab",
        ),
        (
            "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
            "abc",
        ),
        (
            "0c9f157ab030fb06e957c14e3938dc5908962e5dd7b66f04a36fc534",
            "abcd",
        ),
        (
            "880e79bb0a1d2c9b7528d851edb6b8342c58c831de98123b432a4515",
            "abcde",
        ),
        (
            "236c829cfea4fd6d4de61ad15fcf34dca62342adaf9f2001c16f29b8",
            "abcdef",
        ),
        (
            "4767af672b3ed107f25018dc22d6fa4b07d156e13b720971e2c4f6bf",
            "abcdefg",
        ),
        (
            "792e25e0ae286d123a38950007e037d3122e76c4ee201668c385edab",
            "abcdefgh",
        ),
        (
            "56b275d36127dc070cda4019baf2ce2579a25d8c67fa2bc9be61b539",
            "abcdefghi",
        ),
        (
            "f809423cbb25e81a2a64aecee2cd5fdc7d91d5db583901fbf1db3116",
            "abcdefghij",
        ),
        (
            "4c46e10b5b72204e509c3c06072cea970bc020cd45a61a0acdfa97ac",
            "Discard medicine more than two years old.",
        ),
        (
            "cb0cef13c1848d91a6d02637c7c520de1914ad4a7aea824671cc328e",
            "He who has a shady past knows that nice guys finish last.",
        ),
        (
            "6c7bd0f3a6544ea698006c2ea583a85f80ea2913590a186db8bb2f1b",
            "I wouldn't marry him with a ten foot pole.",
        ),
        (
            "981323be3eca6ccfa598e58dd74ed8cb05d5f7f6653b7604b684f904",
            "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave",
        ),
        (
            "e6fbf82df5138bf361e826903cadf0612cb2986649ba47a57e1bca99",
            "The days of the digital watch are numbered.  -Tom Stoppard",
        ),
        (
            "6ec2cb2ecafc1a9bddaf4caf57344d853e6ded398927d5694fd7714f",
            "Nepal premier won't resign.",
        ),
        (
            "7f62f36e716e0badaf4a4658da9d09bea26357a1bc6aeb8cf7c3ae35",
            "For every action there is an equal and opposite government program.",
        ),
        (
            "45adffcb86a05ee4d91263a6115dda011b805d442c60836963cb8378",
            "His money is twice tainted: 'taint yours and 'taint mine.",
        ),
        (
            "51cb518f1f68daa901a3075a0a5e1acc755b4e5c82cb47687537f880",
            "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977",
        ),
        (
            "3b59c5e64b0da7bfc18d7017bf458d90f2c83601ff1afc6263ac0993",
            "It's a tiny change to the code and not completely disgusting. - Bob Manchek",
        ),
        (
            "6a9525c0fac0f91b489bc4f0f539b9ec4a156a4e98bc15b655c2c881",
            "size:  a.out:  bad magic",
        ),
        (
            "a1b2b2905b1527d682049c6a76e35c7d8c72551abfe7833ac1be595f",
            "The major problem is with sendmail.  -Mark Horton",
        ),
        (
            "76cf045c76a5f2e3d64d56c3cdba6a25479334611bc375460526f8c1",
            "Give me a rock, paper and scissors and I will move the world.  CCFestoon",
        ),
        (
            "4473671daeecfdb6f6c5bc06b26374aa5e497cc37119fe14144c430c",
            "If the enemy is within range, then so are you.",
        ),
        (
            "6accb6394758523fcd453d47d37ebd10868957a0a9e81c796736abf8",
            "It's well we cannot hear the screams/That we create in others' dreams.",
        ),
        (
            "6f173f4b6eac7f2a73eaa0833c4563752df2c869dc00b7d30219e12e",
            "You remind me of a TV show, but that's all right: I watch it anyway.",
        ),
        (
            "db05bf4d0f73325208755f4af96cfac6cb3db5dbfc323d675d68f938",
            "C is as portable as Stonehedge!!",
        ),
        (
            "05ffa71bb02e855de1aaee1777b3bdbaf7507646f19c4c6aa29933d0",
            "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley",
        ),
        (
            "3ad3c89e15b91e6273534c5d18adadbb528e7b840b288f64e81b8c6d",
            "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule",
        ),
        (
            "e3763669d1b760c1be7bfcb6625f92300a8430419d1dbad57ec9f53c",
            "How can you write a big system without C++?  -Paul Glick",
        ),
    ];

    let mut sha = SHA::sha512_224();
    let mut digest = Vec::new();
    b.iter(|| {
        cases.iter().for_each(|e| {
            sha.write((e.1).as_bytes());
            sha.checksum(&mut digest);

            sha.checksum(&mut digest);
            sha.reset();
        });
    });
}

#[bench]
fn sha512t256(b: &mut Bencher) {
    let cases = [
        (
            "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
            "",
        ),
        (
            "455e518824bc0601f9fb858ff5c37d417d67c2f8e0df2babe4808858aea830f8",
            "a",
        ),
        (
            "22d4d37ec6370571af7109fb12eae79673d5f7c83e6e677083faa3cfac3b2c14",
            "ab",
        ),
        (
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
            "abc",
        ),
        (
            "d2891c7978be0e24948f37caa415b87cb5cbe2b26b7bad9dc6391b8a6f6ddcc9",
            "abcd",
        ),
        (
            "de8322b46e78b67d4431997070703e9764e03a1237b896fd8b379ed4576e8363",
            "abcde",
        ),
        (
            "e4fdcb11d1ac14e698743acd8805174cea5ddc0d312e3e47f6372032571bad84",
            "abcdef",
        ),
        (
            "a8117f680bdceb5d1443617cbdae9255f6900075422326a972fdd2f65ba9bee3",
            "abcdefg",
        ),
        (
            "a29b9645d2a02a8b582888d044199787220e316bf2e89d1422d3df26bf545bbe",
            "abcdefgh",
        ),
        (
            "b955095330f9c8188d11884ec1679dc44c9c5b25ff9bda700416df9cdd39188f",
            "abcdefghi",
        ),
        (
            "550762913d51eefbcd1a55068fcfc9b154fd11c1078b996df0d926ea59d2a68d",
            "abcdefghij",
        ),
        (
            "690c8ad3916cefd3ad29226d9875965e3ee9ec0d4482eacc248f2ff4aa0d8e5b",
            "Discard medicine more than two years old.",
        ),
        (
            "25938ca49f7ef1178ce81620842b65e576245fcaed86026a36b516b80bb86b3b",
            "He who has a shady past knows that nice guys finish last.",
        ),
        (
            "698e420c3a7038e53d8e73f4be2b02e03b93464ac1a61ebe69f557079921ef65",
            "I wouldn't marry him with a ten foot pole.",
        ),
        (
            "839b414d7e3900ee243aa3d1f9b6955720e64041f5ab9bedd3eb0a08da5a2ca8",
            "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave",
        ),
        (
            "5625ecb9d284e54c00b257b67a8cacb25a78db2845c60ef2d29e43c84f236e8e",
            "The days of the digital watch are numbered.  -Tom Stoppard",
        ),
        (
            "9b81d06bca2f985e6ad3249096ff3c0f2a9ec5bb16ef530d738d19d81e7806f2",
            "Nepal premier won't resign.",
        ),
        (
            "08241df8d91edfcd68bb1a1dada6e0ae1475a5c6e7b8f12d8e24ca43a38240a9",
            "For every action there is an equal and opposite government program.",
        ),
        (
            "4ff74d9213a8117745f5d37b5353a774ec81c5dfe65c4c8986a56fc01f2c551e",
            "His money is twice tainted: 'taint yours and 'taint mine.",
        ),
        (
            "b5baf747c307f98849ec881cf0d48605ae4edd386372aea9b26e71db517e650b",
            "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977",
        ),
        (
            "7eef0538ebd7ecf18611d23b0e1cd26a74d65b929a2e374197dc66e755ca4944",
            "It's a tiny change to the code and not completely disgusting. - Bob Manchek",
        ),
        (
            "d05600964f83f55323104aadab434f32391c029718a7690d08ddb2d7e8708443",
            "size:  a.out:  bad magic",
        ),
        (
            "53ed5f9b5c0b674ac0f3425d9f9a5d462655b07cc90f5d0f692eec093884a607",
            "The major problem is with sendmail.  -Mark Horton",
        ),
        (
            "5a0147685a44eea2435dbd582724efca7637acd9c428e5e1a05115bc3bc2a0e0",
            "Give me a rock, paper and scissors and I will move the world.  CCFestoon",
        ),
        (
            "1152c9b27a99dbf4057d21438f4e63dd0cd0977d5ff12317c64d3b97fcac875a",
            "If the enemy is within range, then so are you.",
        ),
        (
            "105e890f5d5cf1748d9a7b4cdaf58b69855779deebc2097747c2210a17b2cb51",
            "It's well we cannot hear the screams/That we create in others' dreams.",
        ),
        (
            "74644ead770da1434365cd912656fe1aca2056d3039d39f10eb1151bddb32cf3",
            "You remind me of a TV show, but that's all right: I watch it anyway.",
        ),
        (
            "50a234625de5587581883dad9ef399460928032a5ea6bd005d7dc7b68d8cc3d6",
            "C is as portable as Stonehedge!!",
        ),
        (
            "a7a3846005f8a9935a0a2d43e7fd56d95132a9a3609bf3296ef80b8218acffa0",
            "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley",
        ),
        (
            "688ff03e367680757aa9906cb1e2ad218c51f4526dc0426ea229a5ba9d002c69",
            "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule",
        ),
        (
            "3fa46d52094b01021cff5af9a438982b887a5793f624c0a6644149b6b7c3f485",
            "How can you write a big system without C++?  -Paul Glick",
        ),
    ];

    let mut sha = SHA::sha512_256();
    let mut digest = Vec::new();
    b.iter(|| {
        cases.iter().for_each(|e| {
            sha.write((e.1).as_bytes());
            sha.checksum(&mut digest);

            sha.checksum(&mut digest);
            sha.reset();
        });
    });
}
