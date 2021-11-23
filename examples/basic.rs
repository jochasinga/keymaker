use keymaker::{
    bip32::{KeyPair, MasterExtendedKeys},
    bip39::SeedBuilder,
    Network, PublicKey,
};

fn main() {
    let seed = SeedBuilder::new().build().unwrap();
    // Seed string of 128 character-long.
    assert_eq!(seed.to_string().len(), 128);
    // Default mnemonic is a 12-word phase.
    assert_eq!(seed.mnemonic.len(), 12);

    // Create a master extended key from the generated seed.
    let keys = MasterExtendedKeys::new(seed.entropy, None, Network::Testnet, false).unwrap();
    // Derive a child keypair from master private key.
    let kp = KeyPair::from_private(keys.privkey(), false).unwrap();
    assert_eq!(kp.private().secret.len(), 32);

    // A normal public key's length is 65, while a compressed version is 33.
    match kp.pubkey() {
        PublicKey::Standard(inner) => {
            assert_eq!(inner.len(), 65);
            let pubkey_hex = kp.pubkey().to_string();
            println!("normal pubkey: {}", pubkey_hex);
        }
        PublicKey::Compressed(inner) => {
            assert_eq!(inner.len(), 33);
            let pubkey_hex = kp.pubkey().to_string();
            println!("compressed pubkey: {}", pubkey_hex);
        }
    }
}
