//! Basic and Naive implementation of an HMAC algorithm. Purely for learning
//! purposes.

use bigint::BigUint;

/// Contains the secret key for the HMAC algorithm.
pub struct HMAC {
    secret: BigUint,
}

impl HMAC {
    /// Creates a new HMAC struct given an existing secret.
    pub fn from_existing_secret(secret: BigUint) -> HMAC {
        HMAC { secret }
    }

    // /// Creates a message auth `a` given a message and using the secret.
    // /// NOTE(ccdle12): this is a naive implementation.
    // /// Algorithm: H((K' ^ opad) || H((K' ^ ipad) || m))
    // /// 1. outer_xor = (K' ^ opad)
    // /// 2. inner_xor = (K' ^ ipad)
    // /// 3. Concatenate:
    // ///    - inner_concat = inner_xor || m
    // /// 4. Hash inner_concat
    // ///   - ipad_hash = H(inner_concat)
    // /// 5. Concatenate:
    // ///    - preimage = outer_xor || ipad_hash
    // /// 6. Hash the preimage:
    // ///    - a = H(preimage)
    // /// 7. Return the message authentication `a`.
    // ///    - return a.
    // pub fn generate_message_auth() {}
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

        let auth = alice_hmac.generate_message_auth(message);
    }
}
