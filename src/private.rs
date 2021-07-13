use crate::{Secret, Network};
use std::fmt;
use secp256k1::bitcoin_hashes::hex::ToHex;

#[derive(PartialEq)]
pub struct PrivateKey {
    /// The network on which this key is used.
    pub network: Network,
    /// ECDSA key.
    pub secret: Secret,
    /// Determine if this private key is in a compressed form (33 bytes).
    pub compressed: bool,
}

impl fmt::Debug for PrivateKey {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		writeln!(f, "network: {:?}", self.network)?;
		writeln!(f, "secret: {}", self.secret.to_hex())?;
		writeln!(f, "compressed: {}", self.compressed)
	}
}