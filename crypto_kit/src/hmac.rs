//! Basic and Naive implementation of an HMAC algorithm. Purely for learning
//! purposes.

use bigint::BigUint;
use sha2::{Digest, Sha256};

/// Contains the secret key for the HMAC algorithm.
pub struct HMAC {
    secret: BigUint,
}

impl HMAC {
    /// Constants for the implementation of the HMAC.
    const IPAD: [u8; 1] = [0x36];
    const OPAD: [u8; 1] = [0x5c];

    /// Creates a new HMAC struct given an existing secret.
    pub fn from_existing_secret(secret: BigUint) -> HMAC {
        HMAC { secret }
    }

    // NOTE(ccdle12): this is a naive implementation.
    // TODO(ccdle12): K should be subkeys of the seceret.
    // TODO(ccdle12): The opad and ipad should be repeated x amount of times for
    // proper padding.
    /// Creates a hashed authentication given a message and using the secret.
    /// Algorithm: H((K' ^ opad) || H((K' ^ ipad) || m))
    /// 1. outer_xor = (K' ^ opad)
    /// 2. inner_xor = (K' ^ ipad)
    /// 3. Concatenate:
    ///    - inner_concat = inner_xor || m
    /// 4. Hash inner_concat
    ///   - ipad_hash = H(inner_concat)
    /// 5. Concatenate:
    ///    - preimage = outer_xor || ipad_hash
    /// 6. Hash the preimage:
    ///    - a = H(preimage)
    /// 7. Return the message authentication `a`.
    ///    - return a.
    pub fn generate_auth(&self, message: &[u8]) -> Vec<u8> {
        // Calculate inner and out xor.
        let outer_xor = &self.secret ^ BigUint::from_bytes_be(&HMAC::OPAD);
        let inner_xor = &self.secret ^ BigUint::from_bytes_be(&HMAC::IPAD);

        // Concatenate inner_xor and the message.
        // Hash the inner_concat.
        let inner_concat: Vec<u8> = [&inner_xor.to_bytes_be(), message].concat();
        let mut hasher = Sha256::new();
        hasher.input(inner_concat);

        // Calculate the preimage by concatenating the outer_xor and ipad_hash.
        let preimage: Vec<u8> =
            [&outer_xor.to_bytes_be(), hasher.result_reset().as_slice()].concat();

        // Hash the preimage and return the HMAC result as Vec<u8>.
        hasher.input(preimage);
        hasher.result().as_slice().to_vec()
    }

    /// Verifies a message with a hashed authentication message. If the generated
    /// hash of the message is the same as the auth_hash, then we can conclude
    /// the message is valid.
    pub fn check_auth(&self, message: &[u8], auth_hash: &Vec<u8>) -> bool {
        &self.generate_auth(message) == auth_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xor_cipher::generate_secret;

    // Helper function to bootstrap alice and bob with a secret key and hmac.
    fn helper_alice_bob_hmac() -> (HMAC, HMAC) {
        let secret = generate_secret();

        let hmac_alice = HMAC::from_existing_secret(secret.clone());
        let hmac_bob = HMAC::from_existing_secret(secret);

        (hmac_alice, hmac_bob)
    }

    #[test]
    fn init_from_existing_key() {
        let secret = generate_secret();

        let hmac_alice = HMAC::from_existing_secret(secret.clone());
        let hmac_bob = HMAC::from_existing_secret(secret);
    }

    #[test]
    fn encrypt_message_authentication() {
        let (alice_hmac, bob_hmac): (HMAC, HMAC) = helper_alice_bob_hmac();
        let message = String::from("hello");

        let auth = alice_hmac.generate_auth(message.as_bytes());
        println!("auth message: {:?}", auth);

        let check = bob_hmac.generate_auth(message.as_bytes());
        assert_eq!(check, auth);
    }

    #[test]
    fn catch_altered_message() {
        let (alice_hmac, bob_hmac): (HMAC, HMAC) = helper_alice_bob_hmac();
        let message = String::from("attack");

        // Alice generates a message authentication.
        let auth: Vec<u8> = alice_hmac.generate_auth(message.as_bytes());

        // Eve intercepts the message and alters the message, sending it to Bob.
        let altered_message = String::from("retreat");

        // Bob checks the authentication of the received message.
        // The authentication should fail, since eve has changed the messaged.
        let check = bob_hmac.check_auth(altered_message.as_bytes(), &auth);
        assert_eq!(check, false);
    }
}
