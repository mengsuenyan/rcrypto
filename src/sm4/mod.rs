//! SM4 block cipher algorithm   
//! GM/T 0002-2012
//! 
//! https://www.cnblogs.com/mengsuenyan/p/13819849.html


mod sm4_const_tables;
mod  sm4;

pub use sm4::SM4;

#[cfg(test)]
mod sm4_test;