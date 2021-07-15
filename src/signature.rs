//! Bitcoin signatures.
//!
//! http://bitcoin.stackexchange.com/q/12554/40688

use std::{fmt, ops, str};
use std::convert::TryInto;
use secp256k1::bitcoin_hashes::hex::ToHex;
use secp256k1::Signature as SecpSignature;
use secp256k1::SerializedSignature as SecpSerSignature;
use hex;

use crate::{Hash520Bits, Error};

#[derive(PartialEq)]
pub struct Signature(pub Vec<u8>);

impl fmt::Debug for Signature {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		self.0.to_hex().fmt(f)
	}
}

impl fmt::Display for Signature {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		self.0.to_hex().fmt(f)
	}
}

impl ops::Deref for Signature {
	type Target = [u8];

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl From<SecpSerSignature> for Signature {
	fn from(sig: SecpSerSignature) -> Self {
		let mut vec = vec![];
		for v in sig.iter() {
			vec.push(*v);
		}
		Self(vec)
	}
}

impl str::FromStr for Signature {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Error> {
		let vec = hex::decode(s).map_err(|_| Error::InvalidSignature)?;
		Ok(Signature(vec))
	}
}

impl From<&'static str> for Signature {
	fn from(s: &'static str) -> Self {
		s.parse().unwrap()
	}
}

impl From<Vec<u8>> for Signature {
	fn from(v: Vec<u8>) -> Self {
		Signature(v)
	}
}

impl From<Signature> for Vec<u8> {
	fn from(s: Signature) -> Self {
		s.0
	}
}

impl Signature {
	pub fn check_low_s(&self) -> bool {
		unimplemented!();
	}
}

impl<'a> From<&'a [u8]> for Signature {
	fn from(v: &'a [u8]) -> Self {
		Signature(v.to_vec())
	}
}

#[derive(PartialEq)]
pub struct CompactSignature(Hash520Bits);

impl fmt::Debug for CompactSignature {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(&self.0.to_hex())
	}
}

impl fmt::Display for CompactSignature {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(&self.0.to_hex())
	}
}

impl ops::Deref for CompactSignature {
	type Target = [u8];

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl str::FromStr for CompactSignature {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Error> {
		let hash: Hash520Bits = s.as_bytes()
			.try_into()
			.map_err(|_| Error::InvalidSignature)?;
		Ok(CompactSignature(hash))
	}
}

impl From<&'static str> for CompactSignature {
	fn from(s: &'static str) -> Self {
		s.parse().unwrap()
	}
}

impl From<Hash520Bits> for CompactSignature {
	fn from(h: Hash520Bits) -> Self {
		CompactSignature(h)
	}
}