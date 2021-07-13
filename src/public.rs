use crate::{Hash520Bits, Hash264Bits};

#[derive(Debug)]
pub enum PublicKey {
    Standard(Hash520Bits),
    Compressed(Hash264Bits),
}