use crate::crypto;
use crate::Hash520Bits;
use crate::{
    CompactSignature, DisplayLayout, Error, Message, Network, Secret, Signature, SECP256K1,
};
use base58::{FromBase58, ToBase58};
use secp256k1::bitcoin_hashes::hex::ToHex;
use secp256k1::bitcoin_hashes::sha256t::Hash;
use secp256k1::key;
use secp256k1::Message as SecpMessage;
use std::convert::TryInto;
use std::fmt;

#[derive(PartialEq, Clone)]
pub struct PrivateKey {
    /// The network on which this key is used.
    pub network: Network,
    /// ECDSA key.
    pub secret: Secret,
    /// Determine if this private key is in a compressed form (33 bytes).
    pub compressed: bool,
}

impl PrivateKey {
    pub fn sign(&self, message: &Message) -> Result<Signature, Error> {
        let context = &SECP256K1;
        let secret = key::SecretKey::from_slice(&self.secret)?;
        let message = SecpMessage::from_slice(message)?;
        let signature = context.sign(&message, &secret);
        let serialized_sig = signature.serialize_der();
        Ok(Signature::from(serialized_sig))
    }

    pub fn sign_compact(&self, message: &Message) -> Result<CompactSignature, Error> {
        let context = &SECP256K1;
        let secret = key::SecretKey::from_slice(&self.secret)?;
        let message = SecpMessage::from_slice(message)?;
        let signature = context.sign_recoverable(&message, &secret);
        let (recovery_id, data) = signature.serialize_compact();
        let recovery_id = recovery_id.to_i32() as u8;
        let mut signature: Hash520Bits = [0u8; 65];
        signature[1..65].copy_from_slice(&data[0..64]);
        if self.compressed {
            signature[0] = 27 + recovery_id + 4;
        } else {
            signature[0] = 27 + recovery_id;
        }
        Ok(signature.into())
    }
}

impl DisplayLayout for PrivateKey {
    type Target = Vec<u8>;

    fn layout(&self) -> Self::Target {
        let mut result = vec![];
        let network_byte = match self.network {
            Network::Mainnet => 128,
            Network::Testnet => 239,
        };
        result.push(network_byte);
        result.extend(&self.secret);
        if self.compressed {
            result.push(1);
        }
        let cs = crypto::checksum(&result);
        result.extend_from_slice(&cs);
        result
    }

    fn from_layout(data: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let compressed = match data.len() {
            37 => false,
            38 => true,
            _ => return Err(Error::InvalidPrivate),
        };

        if compressed && data[data.len() - 5] != 1 {
            return Err(Error::InvalidPrivate);
        }

        let cs = crypto::checksum(&data[..data.len() - 4]);
        if &data[data.len() - 4..] != &cs {
            return Err(Error::InvalidChecksum);
        }

        let network = match data[0] {
            128 => Network::Mainnet,
            239 => Network::Testnet,
            _ => return Err(Error::InvalidPrivate),
        };

        let mut secret = Secret::default();
        secret.copy_from_slice(&data[1..33]);

        let private = PrivateKey {
            network,
            secret,
            compressed,
        };

        Ok(private)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "network: {:?}", self.network)?;
        writeln!(f, "secret: {}", self.secret.to_hex())?;
        writeln!(f, "compressed: {}", self.compressed)
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.layout().to_base58().fmt(f)
    }
}
