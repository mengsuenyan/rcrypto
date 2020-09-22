

mod md5;

// #[cfg(not(all(rcrypto_sse2 = "support", any(target_arch = "x86", target_arch = "x86_64"))))]
mod md5_generic;

// The performance is not better than the rust due to each step depend on previous
// steps that cannot make full the parallelization of SSE2 instructions.
// #[cfg(all(rcrypto_sse2 = "support", any(target_arch = "x86", target_arch = "x86_64")))]
// mod md5_amd64;

pub use md5::MD5;