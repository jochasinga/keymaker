use anyhow::{Context, Result};
use ring::hmac::{self, HMAC_SHA512};
use secp256k1::{self, key};
use std::convert::TryInto;
use std::fmt;
use std::str;
use thiserror::Error;

use crate::{ChainCode, Network, PrivateKey, PublicKey, SECP256K1};

const DEFAULT_KEY: &str = "default_seed";

/// Error originating from [bip32](bip32) module.
#[derive(Error, Debug)]
pub enum Bip32Error {
    /// The optional key used in the key generation is `None`.
    #[error("This is a bug. Please help report this as an issue.")]
    EmptyKey,
    #[error("Could not convert from slice")]
    TryFromSliceError,
}

/// Define a pair of private and public keys.
pub struct KeyPair {
    private: PrivateKey,
    public: PublicKey,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.private.fmt(f)?;
        writeln!(f, "public: {:?}", self.public)
    }
}

impl fmt::Display for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "private: {}", self.private)?;
        writeln!(f, "public: {}", self.public)
    }
}

impl KeyPair {
    pub fn private(&self) -> &PrivateKey {
        &self.private
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn pubkey(&self) -> &PublicKey {
        &self.public
    }

    pub fn secret(&self) -> &PrivateKey {
        &self.private
    }

    pub fn from_private(private: PrivateKey, compressed: bool) -> Result<Self> {
        let secret_key: key::SecretKey = key::SecretKey::from_slice(&private.secret[..])
            .with_context(|| Bip32Error::TryFromSliceError)?;
        let pub_key = key::PublicKey::from_secret_key(&SECP256K1, &secret_key);

        let public: PublicKey;
        if compressed {
            public = PublicKey::Standard(pub_key.serialize_uncompressed());
        } else {
            public = PublicKey::Compressed(pub_key.serialize());
        }

        Ok(Self { private, public })
    }
}

/// Represents a derivable master key for all child keys.
pub struct MasterExtendedKeys {
    public: PublicKey,
    private: PrivateKey,
    chain_code: ChainCode,
}

impl MasterExtendedKeys {
    /// Create a new [MasterExtendedKeys](MasterExtendedKeys).
    ///
    /// # Arguments
    ///
    /// * `msg` - 64-bit byte array of a seed message derived from [bip32::Seed](bip32::Seed).
    /// * `key` - Optional key. Default to "xerberus_seed".
    ///
    pub fn new(
        msg: [u8; 64],
        mut key: Option<&str>,
        network: Network,
        compressed: bool,
    ) -> Result<Self> {
        if key.is_none() {
            key.replace(DEFAULT_KEY);
        }

        let key = key.with_context(|| Bip32Error::EmptyKey)?;

        let k = hmac::Key::new(HMAC_SHA512, key.as_bytes());
        let tag = hmac::sign(&k, &msg[..]);
        let inner_t = tag.as_ref();

        let private_key: [u8; 32] = inner_t[..inner_t.len() / 2]
            .try_into()
            .with_context(|| Bip32Error::TryFromSliceError)?;

        let chain_code: ChainCode = inner_t[inner_t.len() / 2..]
            .try_into()
            .with_context(|| Bip32Error::TryFromSliceError)?;

        let private = PrivateKey {
            network,
            secret: private_key,
            compressed: false,
        };

        let secret_key: key::SecretKey = key::SecretKey::from_slice(&private_key[..])?;

        let public: PublicKey;
        if compressed {
            let public_key = key::PublicKey::from_secret_key(&SECP256K1, &secret_key).serialize();
            public = PublicKey::Compressed(public_key);
        } else {
            let uncompressed_public_key =
                key::PublicKey::from_secret_key(&SECP256K1, &secret_key).serialize_uncompressed();
            public = PublicKey::Standard(uncompressed_public_key);
        }

        Ok(MasterExtendedKeys {
            public,
            private,
            chain_code,
        })
    }

    pub fn pubkey(&self) -> PublicKey {
        self.public.clone()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::bip39::{Seed, SeedBuilder};
    use anyhow::Result;

    #[test]
    fn key_gen_test() {
        let Seed { entropy, .. } = SeedBuilder::new().build().unwrap();
        let keys = MasterExtendedKeys::new(entropy, None, Network::Testnet, false);

        let MasterExtendedKeys {
            public,
            private,
            chain_code,
        } = keys.unwrap();

        if let PublicKey::Standard(pub_key) = public {
            // Pointless assertions for now.
            assert_eq!(pub_key.len(), 65);
            assert_eq!(private.secret.len(), 32);
            assert_eq!(chain_code.len(), 32);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn keypair_gen() -> Result<()> {
        let Seed { entropy, .. } = SeedBuilder::new().build().unwrap();
        let keys = MasterExtendedKeys::new(entropy, None, Network::Testnet, false)?;
        let _ = KeyPair::from_private(keys.private, false);
        Ok(())
    }

    #[test]
    fn display_keys() -> Result<()> {
        let Seed { entropy, .. } = SeedBuilder::new().build()?;
        let keys = MasterExtendedKeys::new(entropy, None, Network::Testnet, false)?;

        let kp = KeyPair::from_private(keys.private, false)?;

        assert_eq!(kp.private().secret.len(), 32);

        if let PublicKey::Standard(inner) = kp.public() {
            assert_eq!(inner.len(), 65);
        }

        Ok(())
    }
}
