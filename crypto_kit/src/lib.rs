#![allow(dead_code)]
//! A library for cryptography implementations.

extern crate num_bigint as bigint;
extern crate num_traits;
extern crate rand;

mod xor_cipher;

pub use xor_cipher::XORCipher;
