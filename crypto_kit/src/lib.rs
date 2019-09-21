#![allow(dead_code)]
//! A library for cryptography implementations.

extern crate num_bigint as bigint;
extern crate num_traits;
extern crate rand;
extern crate sha2;

mod hmac;
pub mod xor_cipher;

pub use hmac::HMAC;
