


mod const_tables;

mod sha;
pub use sha::SHA;

mod sha1;
pub use sha1::SHA1;

mod sha256;
pub use sha256::{SHA256, SHA224};

mod sha512;

pub use sha512::{SHA384, SHA512T224, SHA512, SHA512T, SHA512T256};

// my computer does not support the SHA instructions, so this amd64 implementation didn't test success.
// #[cfg(all(rcrypto_sha = "support", any(target_arch = "x86", target_arch = "x86_64")))]
// mod sha1_amd64;
// #[cfg(not(all(rcrypto_sha = "support", any(target_arch = "x86", target_arch = "x86_64"))))]
mod sha1_generic;


// my computer does not support the SHA instructions, so this amd64 implementation didn't test success.
// #[cfg(all(rcrypto_sha = "support", any(target_arch = "x86", target_arch = "x86_64")))]
// mod sha256_amd64;
// #[cfg(not(all(rcrypto_sha = "support", any(target_arch = "x86", target_arch = "x86_64"))))]
mod sha256_generic;

mod sha512_generic;