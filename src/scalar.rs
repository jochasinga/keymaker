use std::ops::Add;
use std::convert::TryInto;
use num::BigUint;

pub trait Mod {
    type Output;
    fn modulo(self, other: Self) -> Self;
}

pub trait Scalar: Add + Mod
where Self : Sized {}


fn modulo(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    if a.len() != b.len() {
        panic!("");
    }
    let big_a = BigUint::from_bytes_be(&a[..]);
    let big_b = BigUint::from_bytes_be(&b[..]);
    let big_result = big_a % big_b;
    let mut bytes = BigUint::to_bytes_be(&big_result);
    if bytes.len() < a.len() {
        let mut padder = vec![0u8; a.len() - bytes.len()];
        for byte in &bytes {
            padder.push(*byte);
        }
        bytes = padder;
    }
    bytes
}

fn add_bytes(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    if a.len() != b.len() {
        panic!("");
    }
    let mut wtr: Vec<u8> = vec![];
    let mut carry: u8 = 0;
    for (i, &num_a) in a.iter().enumerate() {
        let mut result = num_a as u16 + b[i] as u16 + carry as u16;
        if result > 255 {
            carry = (result - 255) as u8;
            result = 255;
        } else {
            carry = 0;
        }
        wtr.push(result.try_into().unwrap());
    }
    wtr
}

pub struct BytesArray(Vec<u8>);

impl BytesArray {
    pub fn new(bytes: Vec<u8>) -> Self {
        BytesArray(bytes)
    }
}

impl Scalar for BytesArray {}

impl Mod for BytesArray {
    type Output = Self;
    fn modulo(self, divisor: Self) -> Self {
        let (Self(a), Self(b)) = (self, divisor);
        Self(modulo(a, b))
    }
}
impl Add for BytesArray {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        let (Self(a), Self(b)) = (self, other);
        Self(add_bytes(a, b))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_add_bytes_array() {
        let a = u16::to_be_bytes(65500);
        let b = u16::to_be_bytes(35);
        let c = u128::to_be_bytes(5_000_000);
        let d = u128::to_be_bytes(1_000_000);

        let a_bytes = BytesArray::new(a[..].to_vec());
        let b_bytes = BytesArray::new(b[..].to_vec());
        let result = a_bytes + b_bytes;
        let BytesArray(inner) = result;
        let result: [u8; 2] = inner.try_into().unwrap();
        assert_eq!(u16::from_be_bytes(result), 65500 + 35);

        let c_bytes = BytesArray::new(c[..].to_vec());
        let d_bytes = BytesArray::new(d[..].to_vec());
        let result = c_bytes + d_bytes;
        let BytesArray(inner) = result;
        let result: [u8; 16] = inner.try_into().unwrap();
        assert_eq!(u128::from_be_bytes(result), 6_000_000 + 1_000_000);
    }

    #[test]
    fn test_modulo_bytes_array() {
        let a = u16::to_be_bytes(65500);
        let b = u16::to_be_bytes(35);

        let a_bytes = BytesArray::new(a[..].to_vec());
        let b_bytes = BytesArray::new(b[..].to_vec());
        let result = a_bytes.modulo(b_bytes);
        let BytesArray(inner) = result;
        let result: [u8; 2] = inner.try_into().unwrap();
        assert_eq!(u16::from_be_bytes(result), 65500_u16.rem_euclid(35));

        let c = u128::to_be_bytes(6_000_000);
        let d = u128::to_be_bytes(120_000);
        let c_bytes = BytesArray::new(c[..].to_vec());
        let d_bytes = BytesArray::new(d[..].to_vec());
        let result = c_bytes.modulo(d_bytes);
        let BytesArray(inner) = result;
        let result: [u8; 16] = inner.try_into().unwrap();
        assert_eq!(u128::from_be_bytes(result), 6_000_000_u128.rem_euclid(120_000));
    }
}





