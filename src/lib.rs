pub mod bip32;
pub mod bip39;
mod network;
mod private;
mod public;
mod display;
mod crypto;
mod error;


/// Re-exported for convenience.
///
/// ```
/// use xerberus::*;
/// let seed = SeedBuilder::new().size(MnemonicSize::Size256Bits).build().unwrap();
/// ```
pub use bip39::{MnemonicSize, SeedBuilder, Seed};
pub use bip32::{KeyPair, MasterExtendedKeys};
pub use network::Network;
pub use private::PrivateKey;
pub use public::PublicKey;
pub use display::DisplayLayout;
pub use error::Error;


use lazy_static::lazy_static;


type Hash32Bits  = [u8; 4];
type Hash160Bits = [u8; 20];
type Hash256Bits = [u8; 32];
type Hash264Bits = [u8; 33];
type Hash520Bits = [u8; 65];

/// 20-byte long hash derived from public `ripemd160(sha256(public))`
pub type AddressHash = Hash160Bits;
/// 32-byte long secret key
pub type Secret = Hash256Bits;
/// 32-byte long signable message
pub type Message = Hash256Bits;
/// 32-byte long chain code
pub type ChainCode = Hash256Bits;

lazy_static! {
    pub static ref SECP256K1: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}
