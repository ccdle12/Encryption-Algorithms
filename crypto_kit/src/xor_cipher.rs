use bigint::BigUint;
use bigint::RandBigInt;
use num_traits::FromPrimitive;

pub struct XORCipher {
    /// Base 36 radix is used. The message space can only contain the following
    /// characters: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".
    radix: u32,

    /// The bit range for generating a random number.
    bit_range: usize,
}

impl XORCipher {
    /// Constructor with default values of radix = 36 and bit_range = 256.
    pub fn new() -> XORCipher {
        XORCipher {
            radix: 36,
            bit_range: 256 as usize,
        }
    }

    /// Generates a secret (BigUint) as 256 bits.
    pub fn generate_secret(&self) -> BigUint {
        rand::thread_rng().gen_biguint(self.bit_range)
    }

    /// Encrypts a given a message (bytes) and a secret used as the cipher.
    pub fn encrypt_message(&self, message: &[u8], secret: &BigUint) -> String {
        self.big_uint_to_str(self.encrypt(self.bytes_to_biguint(message), secret))
    }

    // Internal helper function, converts a biguint to a string.
    pub fn big_uint_to_str(&self, message: BigUint) -> String {
        message.to_str_radix(self.radix)
    }

    // Internal helper function, encrypts a message given a secret. Since this is a
    // simple XOR, encryption and decryption are the same.
    pub fn encrypt(&self, message: BigUint, secret: &BigUint) -> BigUint {
        message ^ secret
    }

    // Internal helper function, parses a message to a BigUint.
    pub fn bytes_to_biguint(&self, message: &[u8]) -> BigUint {
        BigUint::parse_bytes(message, self.radix).expect("failed to parse message while encrypting")
    }

    /// Decrypts a given cipher text (bytes) and a secret.
    //  DEV NOTES(ccdle12):
    //  Has the same implemenation as `encrypt_message` but for clarity the function
    //  has a different name.
    pub fn decrypt_message(&self, cipher_text: &[u8], secret: &BigUint) -> String {
        self.encrypt_message(cipher_text, secret)
    }

    /// A function that demonstrates basic exhaustive_search, not meant to be used
    /// in any real world application.
    pub fn exhaustive_search(
        &self,
        message: &String,
        cipher_text: &String,
        start: u32,
        end: u32,
    ) -> bool {
        for i in start..end {
            let secret_guess = BigUint::from_u32(i).unwrap();
            if message == &self.decrypt_message(cipher_text.as_bytes(), &secret_guess) {
                return true;
            }
        }
        false
    }
}

// fn encrypt_message(message: String, secret: BigInt)
#[cfg(test)]
mod test {
    use super::*;
    use num_traits::Zero;

    #[test]
    fn generate_random_bigint() {
        // Simple random number assumption.
        let mut rng = rand::thread_rng();
        let random_big_num = rng.gen_biguint(1000);
        assert!(random_big_num > Zero::zero());
    }

    #[test]
    fn simple_biguint_from_u8() {
        let m = b"attack";
        let bytes = BigUint::parse_bytes(m, 36).unwrap();
    }

    #[test]
    fn simple_xor() {
        // Simply xors a message space according a simple secret and decrypts.
        // **Encryption:**
        // 5  (message):           0000 0101
        // 10 (secret):            0000 1010
        // ---------------------------------
        // cipher_text:            0000 1111
        //
        // **Decryption:**
        // cipher_text:            0000 1111
        // 10 (secret):            0000 1010
        // ---------------------------------
        // decrypted_text:         0000 0101
        let message = 5;
        let secret = 10;

        // Create the cipher_text using XOR on the message and secret.
        // Using this simple example, the cipher text should be 15.
        let cipher_text = message ^ secret;
        assert!(cipher_text == 15);

        // Decrypt the cipher text using XOR with the secret. It should be equal
        // to the original message.
        let decrypted_message = cipher_text ^ secret;
        assert!(decrypted_message == message);

        // Small keyspaces are easy to break with exhaustive searches.
        let mut secret_guess = 0;
        loop {
            if message == cipher_text ^ secret_guess {
                break;
            }

            secret_guess = secret_guess + 1;
        }
        // Assert that the secret has been found.
        assert!(secret_guess == secret);
    }

    #[test]
    fn big_num_xor() {
        // Alice and Bob are communicating with a shared secret (large random
        // number). Eve is attempting to read the message.
        let xor_cipher = XORCipher::new();
        let secret = xor_cipher.generate_secret();
        let message = "attack";

        // Alice encrypts the messages with the secret.
        let cipher_text = xor_cipher.encrypt_message(message.as_bytes(), &secret);
        println!("Encrypted message: {:?}", cipher_text);

        // Alice sends the cipher text on an insecure channel to Bob.
        // Bob receives it and recovers the plaintext.
        let decrypted_message = xor_cipher.decrypt_message(cipher_text.as_bytes(), &secret);
        println!("Decrypted message: {:?}", decrypted_message);
        assert!(decrypted_message == "attack");

        // Eve intercepts the message and attempts to break the cipher.
        // For brevity, we will limit the exhausitve search.
        for i in 0..1000 {
            let secret_guess = BigUint::from_u32(i).unwrap();
            if message == xor_cipher.decrypt_message(cipher_text.as_bytes(), &secret_guess) {
                panic!();
            }
        }
    }
}
