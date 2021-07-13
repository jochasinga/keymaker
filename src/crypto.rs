pub use crypto::digest::Digest;
use std::hash::Hasher;
use crypto::sha2::Sha256;
use crypto::ripemd160::Ripemd160;
use crate::{Hash32Bits, Hash256Bits};

pub struct DHash256 {
    hasher: Sha256,
}

impl Default for DHash256 {
    fn default() -> Self {
        DHash256 {
            hasher: Sha256::new(),
        }
    }
}

impl DHash256 {
	pub fn new() -> Self {
		DHash256::default()
	}

	pub fn finish(mut self) -> Hash256Bits {
		let mut result = Hash256Bits::default();
		self.result(&mut result);
		result
	}
}

impl Digest for DHash256 {
	fn input(&mut self, d: &[u8]) {
		self.hasher.input(d)
	}

	fn result(&mut self, out: &mut [u8]) {
		self.hasher.result(out);
		self.hasher.reset();
		self.hasher.input(out);
		self.hasher.result(out);
	}

	fn reset(&mut self) {
		self.hasher.reset();
	}

	fn output_bits(&self) -> usize {
		256
	}

	fn block_size(&self) -> usize {
		64
	}
}

#[inline]
pub fn dhash256(input: &[u8]) -> Hash256Bits {
    let mut result = Hash256Bits::default();
    let mut hasher = DHash256::new();
    hasher.input(input);
    hasher.result(&mut result);
    result
}

pub fn checksum(data: &[u8]) -> Hash32Bits {
    let mut result = Hash32Bits::default();
    result.copy_from_slice(&dhash256(data)[..4]);
    result
}