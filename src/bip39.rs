use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::{num::NonZeroU32};
use std::str;
use rand_core::{RngCore, OsRng};
use to_binary::BinaryString;
use std::path::Path;
use ring::{digest, pbkdf2};
use hex;
use anyhow::{Context, Result};
use thiserror::Error;

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;
const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
const DEFAULT_PDKF2_ITERATIONS: u32 = 100_000;
const BYTE_LEN: usize = 8;
const BLOCK_SIZE: usize = 11;
const TWO_BYTES_LEN: usize = 16;
const FOUR_BYTES_LEN: usize = 32;
const SIZE_128_BITS: usize = 128;
const SIZE_256_BITS: usize = 256;
const BITS_PER_CHECKSUM_DIGIT: usize = 32;
const DEFAULT_PASSPHRASE: &str = "";
const DEFAULT_SALT_BASE: &str = "mnemonic";
const WORDLIST_PATH: &str = "./wordlist.txt";

/// Error originating from [bip39](bip39) module.
#[derive(Error, Debug)]
pub enum Bip39Error {

    #[error("Error parsing binary string {0}")]
    ParseBinError(String),

    #[error("Missing file or directory {0}")]
    MissingFileOrDirectory(String),

    #[error("Error opening file {0}. Please report a bug.")]
    FileError(String),

    #[error("Error creating interations for PDKF2 encoding with iteration = {0}. Please report a bug.")]
    Pdkf2IterError(u32)
}

/// Define convenient aliases for the bit size of the seed.
///
/// # Examples
///
/// ```
/// use xerberus::bip39::{SeedBuilder, MnemonicSize};
/// let seed = SeedBuilder::new().size(MnemonicSize::Size256Bits)
///     .build().unwrap();
/// ```
pub enum MnemonicSize {
    Size128Bits,
    Size256Bits,
    Size16Bytes,
    Size32Bytes,
    Size12Words,
    Size24Words,
}

type Credential = [u8; CREDENTIAL_LEN];

/// Build a mnemonic [Seed](Seed) with a few options.
///
/// # Examples
///
/// ```
/// use xerberus::bip39::SeedBuilder;
/// let seed = SeedBuilder::new().build().unwrap();
/// ```
pub struct SeedBuilder<'a> {
    passphrase: &'a str,
    salt: Option<Vec<u8>>,
    bits: usize,
}

impl<'a> Default for SeedBuilder<'a> {
    fn default() -> Self {
        let salt = DEFAULT_SALT_BASE.to_string() + DEFAULT_PASSPHRASE;
        SeedBuilder {
            passphrase: DEFAULT_PASSPHRASE,
            salt: Some(salt.as_bytes().to_vec()),
            bits: SIZE_128_BITS,
        }
    }
}

impl<'a> SeedBuilder<'a> {
    /// Instantiate a default [SeedBuilder](SeedBuilder).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the mnemonic size of the seed.
    ///
    /// # Arguments
    ///
    /// * `size` - A [MnemonicSize](MnemonicSize) that represents the size in bits.
    ///
    /// # Examples
    ///
    /// ```
    /// use xerberus::bip39::{SeedBuilder, MnemonicSize};
    /// let seed_256_bits = SeedBuilder::new()
    ///     .size(MnemonicSize::Size256Bits)
    ///     .build().unwrap();
    /// ```
    pub fn size(mut self, size: MnemonicSize) -> Self {
        use MnemonicSize::*;
        match size {
            Size128Bits
            | Size12Words
            | Size16Bytes => {
                self.bits = SIZE_128_BITS;
            }
            Size256Bits
            | Size24Words
            | Size32Bytes => {
                self.bits = SIZE_256_BITS;
            }
        }
        self
    }

    /// Set the mnemonic size of the seed in bits.
    /// The default value is 128 bits.
    ///
    /// # Argumentss
    ///
    /// * `bits` - A usize that represents the size in bits (128 or 256).
    ///
    /// # Examples
    ///
    /// ```
    /// use xerberus::bip39::SeedBuilder;
    /// let seed_256_bits = SeedBuilder::new()
    ///     .bits(256)
    ///     .build().unwrap();
    /// ```
    pub fn bits(mut self, bits: usize) -> Self {
        self.bits = bits;
        self
    }

    /// Set the optional salt of the seed.
    /// The default value is "mnemonic" + {passphrase}.
    ///
    /// # Argumentss
    ///
    /// * `salt` - A Vec<u8> that represents the salt string.
    ///
    /// # Examples
    ///
    /// ```
    /// use xerberus::bip39::SeedBuilder;
    /// use rand_core::{RngCore, OsRng};
    ///
    /// // Set a random 8-byte salt.
    /// let mut rand = [0u8; 8];
    /// OsRng.fill_bytes(&mut rand);
    ///
    /// let default_builder = SeedBuilder::new();
    /// let custom_builder = SeedBuilder::new()
    ///     .passphrase("holymoly")
    ///     .salt(rand[..].to_vec());
    /// ```
    pub fn salt(mut self, salt: Vec<u8>) -> Self {
        self.salt.replace(salt);
        self
    }

    pub fn passphrase(mut self, passphrase: &'a str) -> Self {
        self.passphrase = passphrase;
        let salt = DEFAULT_SALT_BASE.to_string() + passphrase;
        self.salt.replace(salt.as_bytes().to_vec());
        self
    }

    pub fn build(self) -> Result<Seed, Bip39Error> {
        let mut key: Vec<u8>;
        match self.bits {
            256 => {
                key = vec![0u8; FOUR_BYTES_LEN];
            }
            128 | _ => {
                key = vec![0u8; TWO_BYTES_LEN];
            }
        }

        OsRng.fill_bytes(&mut key);

        let result = digest::digest(&digest::SHA256, &key);
        let BinaryString(b) = BinaryString::from(result.as_ref());

        let BinaryString(bin) = BinaryString::from(&key[..]);
        let checksum_digits = bin.len() / BITS_PER_CHECKSUM_DIGIT;
        let checksum = &b[..checksum_digits];
        let ent = bin + checksum;

        let subs = ent.as_bytes()
            .chunks(BLOCK_SIZE)
            .map(str::from_utf8)
            .collect::<Result<Vec<&str>, _>>()
            .unwrap();

        let indices: Vec<usize> = subs.iter()
            .map(|b| {
                let intval = isize::from_str_radix(b, 2)
                    .with_context(|| Bip39Error::ParseBinError(b.to_string()))
                    .unwrap();
                intval as usize
            })
            .collect();

        let path = Path::new(WORDLIST_PATH);
        if !path.exists() {
            return Err(Bip39Error::MissingFileOrDirectory(WORDLIST_PATH.to_string()));
        }

        let file = File::open(path)
            .with_context(|| Bip39Error::FileError(WORDLIST_PATH.to_string()))
            .unwrap();

        let reader = BufReader::new(file);
        let words: Vec<String> = reader.lines().into_iter()
            .map(|o| o.unwrap())
            .collect();

        let mnemonic_words: Vec<String> = indices.iter().map(|i| {
            words[*i].to_owned()
        }).collect();

        let mut salt = (DEFAULT_SALT_BASE.to_string() + self.passphrase).as_bytes().to_vec();
        if let Some(s) = self.salt {
            salt = s;
        }

        let password = mnemonic_words.join(" ");
        let mut seed_store: Credential = [0u8; CREDENTIAL_LEN];
        let iterations = NonZeroU32::new(DEFAULT_PDKF2_ITERATIONS)
            .with_context(|| Bip39Error::Pdkf2IterError(DEFAULT_PDKF2_ITERATIONS))
            .unwrap();
        pbkdf2::derive(PBKDF2_ALG, iterations, &salt,
                        password.as_bytes(), &mut seed_store);

        let hex_str = hex::encode(&seed_store[..]);

        Ok(Seed {
            mnemonic: mnemonic_words,
            hex: hex_str,
            entropy: seed_store,
        })
    }
}

/// Container of the mnemonic code words, the entropy byte array, and hex string.
/// Use [SeedBuilder](SeedBuilder) to create.
///
/// # Examples
///
/// ```
/// use xerberus::bip39::SeedBuilder;
/// let seed = SeedBuilder::new().build().unwrap();
/// ```
pub struct Seed {
    pub mnemonic: Vec<String>,
    pub entropy: Credential,
    pub hex: String,
}

impl ToString for Seed {
    fn to_string(&self) -> String {
        if self.hex.len() <= 0 {
            return hex::encode(&self.entropy[..]);
        }
        self.hex.to_owned()
    }
}

impl Seed {
    pub fn validate(&self) -> bool {
        let file = File::open(Path::new(WORDLIST_PATH)).unwrap();
        let reader = BufReader::new(file);
        let words: Vec<String> = reader.lines().into_iter()
            .map(|o| o.unwrap())
            .collect();

        let mut indices: Vec<usize> = Vec::with_capacity(self.mnemonic.len());
        for keyword in self.mnemonic.clone() {
            for (i, word) in (&words).into_iter().enumerate() {
                if keyword == *word {
                    indices.push(i);
                }
            }
        }

        let subs: Vec<String> = indices.into_iter().map(|i| format!("{:011b}", i)).collect();
        let ent = subs.join("");

        let checksum_size = match self.mnemonic.len() {
            12 => SIZE_128_BITS,
            24 => SIZE_256_BITS,
            _ => SIZE_128_BITS,
        };

        let checksum_digits = checksum_size / BITS_PER_CHECKSUM_DIGIT;
        let bin = &ent[..ent.len()-4];
        let checksum = &ent[ent.len()-4..];

        let key: Vec<u8> = bin.as_bytes()
            .chunks(BYTE_LEN)
            .map(|i| {
                let b = str::from_utf8(i).unwrap();
                let intval = isize::from_str_radix(b, 2).unwrap();
                intval as u8
            }).collect();

        let hash = digest::digest(&digest::SHA256, &key);
        let BinaryString(b) = BinaryString::from(hash.as_ref());
        &b[..checksum_digits] == checksum
    }
}


#[cfg(test)]
mod tests {

    use super::*;

    const BYTE_LEN: usize = 8;
    enum Error {
        WrongUsernameOrPassword
    }

    #[test]
    fn test_seed_building() -> Result<(), Bip39Error> {
        let mut rand = [0u8; 16];
        OsRng.fill_bytes(&mut rand);

        let default_builder = SeedBuilder::new();
        let custom_builder = SeedBuilder::new()
            .passphrase("holymoly")
            .salt(rand[..].to_vec())
            .bits(256);

        assert_eq!(default_builder.bits, 128);
        assert_eq!(default_builder.passphrase, "");
        assert_eq!(default_builder.salt.to_owned().unwrap(), "mnemonic".as_bytes().to_vec());
        assert_eq!(custom_builder.bits, 256);
        assert_eq!(custom_builder.passphrase, "holymoly");
        assert_eq!(custom_builder.salt.to_owned().unwrap(), rand[..].to_vec());

        let default_seed = default_builder.build()?;
        let custom_seed = custom_builder.build()?;

        let next_builder = SeedBuilder::new()
            .size(MnemonicSize::Size32Bytes)
            .build()?;

        assert_eq!(default_seed.mnemonic.len(), 12);
        assert_eq!(custom_seed.mnemonic.len(), 24);
        assert_eq!(next_builder.mnemonic.len(), 24);
        assert_eq!(default_seed.entropy.len(), 64);
        assert_eq!(custom_seed.entropy.len(), 64);
        Ok(())
    }

    #[test]
    fn validate_mnemonic() -> Result<(), Bip39Error> {
        use hex::{decode_to_slice as hex_decode_to_slice};
        let salt = "mysalt".as_bytes().to_vec();

        let seed = SeedBuilder::new()
            .salt(salt.clone()).build().unwrap();

        let Seed { mnemonic, hex, ..  } = &seed;

        let password = mnemonic.join(" ");
        let mut store = [0u8; CREDENTIAL_LEN];
        hex_decode_to_slice(hex, &mut store).unwrap();

        let pdkf2_iterations = NonZeroU32::new(DEFAULT_PDKF2_ITERATIONS)
            .ok_or(Bip39Error::Pdkf2IterError(DEFAULT_PDKF2_ITERATIONS))?;
        if let Ok(verified) = pbkdf2::verify(PBKDF2_ALG, pdkf2_iterations, &salt,
            password.as_bytes(),
            &store)
            .map_err(|_| Error::WrongUsernameOrPassword) {
            assert_eq!(verified, ());
        } else {
            assert!(false);
        }


        let file = File::open(Path::new(WORDLIST_PATH)).unwrap();
        let reader = BufReader::new(file);

        let words: Vec<String> = reader.lines().into_iter()
            .map(|o| o.unwrap())
            .collect();

        let mut indices: Vec<usize> = Vec::with_capacity(mnemonic.len());

        for keyword in mnemonic.clone() {
            for (i, word) in (&words).into_iter().enumerate() {
                if keyword == *word {
                    indices.push(i);
                }
            }
        }

        let subs: Vec<String> = indices.into_iter().map(|i| format!("{:011b}", i)).collect();
        let ent = subs.join("");
        let checksum_digits = SIZE_128_BITS / BITS_PER_CHECKSUM_DIGIT;
        let bin = &ent[..ent.len()-4];
        let checksum = &ent[ent.len()-4..];

        let key: Vec<u8> = bin.as_bytes()
            .chunks(BYTE_LEN)
            .map(|i| {
                let b = str::from_utf8(i).unwrap();
                let intval = isize::from_str_radix(b, 2).unwrap();
                intval as u8
            }).collect();

        let hash = digest::digest(&digest::SHA256, &key);
        let BinaryString(b) = BinaryString::from(hash.as_ref());
        assert_eq!(&b[..checksum_digits], checksum);
        assert!(seed.validate());

        Ok(())
    }
}
