use std::fmt;
use secp256k1::bitcoin_hashes::hex::ToHex;
use crate::{Hash520Bits, Hash264Bits};

pub enum PublicKey {
    Standard(Hash520Bits),
    Compressed(Hash264Bits),
}

impl fmt::Debug for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			PublicKey::Standard(ref hash) => writeln!(f, "normal: {}", hash.to_hex()),
			PublicKey::Compressed(ref hash) => writeln!(f, "compressed: {}", hash.to_hex()),
		}
	}
}

impl fmt::Display for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Standard(inner) => inner.to_hex().fmt(f),
            Self::Compressed(inner) => inner.to_hex().fmt(f),
        }
	}
}