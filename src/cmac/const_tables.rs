//! https://op.dr.eck.cologne/en/theme/crypto_karisik/eax_cmac_problem.shtml
//! Block size 	Calculation 	Polynomal (hex) 	Polynomal (bit)
//! 32 	2^7+2^3+2^2+1 	0x8D 	10001101
//! 48 	2^5+2^3+2^2+1 	0x2D 	101101
//! 64 	2^4+2^3+2^1+1 	0x1B 	11011
//! 96 	2^10+2^9+2^6+1 	0x641 	11001000001
//! 128 	2^7+2^2+2^1+1 	0x87 	10000111
//! 160 	2^5+2^3+2^2+1 	0x2D 	101101
//! 192 	2^7+2^2+2^1+1 	0x87 	10000111
//! 224 	2^9+2^8+2^3+1 	0x309 	1100001001
//! 256 	2^10+2^5+2^2+1 	0x425 	10000100101
//! 320 	2^4+2^3+2^1+1 	0x1B 	11011
//! 384 	2^12+2^3+2^2+1 	0x100D 	1000000001101
//! 448 	2^11+2^6+2^4+1 	0x851 	100001010001
//! 512 	2^8+2^5+2^2+1 	0x125 	100100101
//! 768 	2^19+2^17+2^4+1 	0xA0011 	10100000000000010001
//! 1024 	2^19+2^6+2^1+1 	0x80043 	10000000000001000011
//! 2048 	2^19+2^14+2^13+1 	0x86001 	10000110000000000001

pub(super) const RB_32: u32 = 0x8d;
pub(super) const RB_48: u32 = 0x2d;
pub(super) const RB_64: u32 = 0x1b;
pub(super) const RB_96: u32 = 0x641;
pub(super) const RB_128: u32 = 0x87;
pub(super) const RB_160: u32 = 0x2d;
pub(super) const RB_192: u32 = 0x87;
pub(super) const RB_224: u32 = 0x309;
pub(super) const RB_256: u32 = 0x425;
pub(super) const RB_320: u32 = 0x1b;
pub(super) const RB_384: u32 = 0x100d;
pub(super) const RB_448: u32 = 0x851;
pub(super) const RB_512: u32 = 0x125;
pub(super) const RB_768: u32 = 0xa0011;
pub(super) const RB_1024: u32 = 0x80043;
pub(super) const RB_2048: u32 = 0x86001;

