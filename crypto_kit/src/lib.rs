#![allow(dead_code)]
//! A library for cryptography implementations.

extern crate num_bigint as bigint;
extern crate num_traits;
extern crate rand;

mod hmac;
pub mod xor_cipher;

pub use hmac::HMAC;
// pub use xor_cipher::XORCipher;
// pub use xor_cipher;
