# keymaker

Hierarchical deterministic (HD) wallet library for crypto wallet.


## structures

The project consists of the core modules named after the corresponding Bitcoin Improvement Proposals:

- [bip39](src/bip39): Implementation of [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) 128-bit and 256-bit mnemonic seed generator.

- [bip32](src/bip32): Implementation of [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) Hierarchical deterministic wallet.

## BIP39

128- to 256-bit mnemonic seed generator.

### 1. Generate entropy

Generate entropy as a source of randomness. The entropy **must be a multiple of 32 bits** between
128 to 256 bits. You should end up with a binary string of size *n* bits.

```
001001001011111000111100001111011011010101010000000111110000111000111011110011101000...
```

### 2. Entropy to mnemonic

Hash the entropy through SHA256, giving us a unique *fingerprint*. Then, take 1 lease significance bit (starting from left-hand side) of that hash *for every 32 bits of entropy*. So, that's 2 LSB for a 64-bit entropy, 3 LSB for a 96-bit entropy, and so on. Append those extra bits to the original entropy binary string.
If the original string was 128 bits, it will become 132 bits (128 + 4 extra bits from the hash of itself).

Next, split up the entropy into groups of 11 bits (it should be equally divided by 11). Convert each group of 11-digit binary number to decimal number, and use it as an index to the [2048-word list](./wordlist.txt).

### 3. Mnemonic to seed

Finally, we can convert the mnemonic sentence (all mnemonic phrases concatenated into a single string) into a 64-byte random seed by using a password-hashing PBKDF2 function to hash the sentence several rounds, along with an optional passphrase as a salt (default salt is empty string "", prepended with the string "mnemonic"). Your mnemonic sentence is effectively your password.

You end up with the 64 random bytes as a seed for the [BIP32](#bip32) steps.

## BIP32

This is an example of a 64 random byte string retrieved from the previous step:

```
b1680c7a6ea6ed5ac9bf3bc3b43869a4c77098e60195bae51a94159333820e125c3409b8c8d74b4489f28ce71b06799b1126c1d9620767c2dadf642cf787cf36
```

### 1. Master Extended Keys
The first step is to create the master keys. This is done by putting the 64 random bytes and an arbitrary key (default to string "default_seed") through the HMAC-SHA512 hash function.

This is passed in as the first `msg` parameter in `bip32::MasterExtendedKeys::new(msg: [u8; 64], key: Option<&str>, ...)`.

The HMAC function returns a new 64 bytes data. **Split this into two halves to create the master keys**.

- The left half is the **private key**.
- The right half is the **chain code**, which is an extra 32 bytes of random data that is required to generate child keys.

If someone got hold of the private key but *not* the chain code, they wouldn't be able to derive the descendant keys (thereby protecting them).

#### Extended Private Key

WIP

#### Extended Public Key

WIP

### 2. Extended Key Tree

WIP

- Normal
- Hardened

### 3. Child Extended Key Derivation

#### 3.1 Normal Child `extended private key`

WIP

#### 3.2 Hardened Child `extended private key`

WIP

#### 3.3 Normal Child `extended public key`

WIP

#### 3.4 Hardened Child `extended public key`

WIP

### Serialization

WIP







### Resources:
- [Mastering Bitcoin](https://www.oreilly.com/library/view/mastering-bitcoin/9781491902639/ch04.html#hd_wallets)
- [learnmeabitcoin.com](https://learnmeabitcoin.com/technical/hd-wallets)
