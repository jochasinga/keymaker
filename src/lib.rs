pub mod bip32;
pub mod bip39;

/// Re-exported for convenience.
///
/// ```
/// use xerberus::*;
/// let seed = SeedBuilder::new().size(MnemonicSize::Size256Bits).build().unwrap();
/// ```
pub use crate::bip39::{MnemonicSize, SeedBuilder, Seed};