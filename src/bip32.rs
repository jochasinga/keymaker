use std::str;
use std::convert::TryInto;
use ring::{hmac::{self, HMAC_SHA512}};
use anyhow::{self, Context, Result};
use thiserror::Error;

const DEFAULT_KEY: &str = "xerberus_seed";

/// Error originating from [bip32](bip32) module.
#[derive(Error, Debug)]
pub enum Bip32Error {
    /// The optional key used in the key generation is `None`.
    #[error("This is a bug. Please help report this as an issue.")]
    EmptyKey,
}


/// Represents a derivable master key for all child keys.
#[derive(Debug)]
pub struct MasterExtendedKeys {
    private_key: [u8; 32],
    chain_code: [u8; 32],
}

impl MasterExtendedKeys {
    /// Create a new [MasterExtendedKeys](MasterExtendedKeys).
    ///
    /// # Arguments
    ///
    /// * `msg` - 64-bit byte array of a seed message derived from [bip32::Seed](bip32::Seed).
    /// * `key` - Optional key. Default to "xerberus_seed".
    ///
    fn new(msg: [u8; 64], mut key: Option<&str>) -> Result<Self, Bip32Error> {
        if key.is_none() {
            key.replace(DEFAULT_KEY);
        }
        if let Some(key) = key {
            let k = hmac::Key::new(HMAC_SHA512, key.as_bytes());
            let tag = hmac::sign(&k, &msg[..]);

            println!("tag: {:?}", tag);

            let inner_t = tag.as_ref();
            let private_key = inner_t[..inner_t.len()/2].try_into().expect(":(");
            let chain_code = inner_t[inner_t.len()/2..].try_into().expect(";(");
            Ok(MasterExtendedKeys {
                private_key,
                chain_code,
            })
        } else {
            Err(Bip32Error::EmptyKey)
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::bip39::{Seed, SeedBuilder};

    #[test]
    fn key_gen_test() {
        let Seed{ entropy, ..} = SeedBuilder::new().build().unwrap();
        let keys = MasterExtendedKeys::new(entropy, None);
        let MasterExtendedKeys{ private_key, chain_code } = keys.unwrap();
        assert_eq!(private_key.len(), 32);
        assert_eq!(chain_code.len(), 32);
    }
}