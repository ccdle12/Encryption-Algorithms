use bigint::BigUint;
use bigint::RandBigInt;

/// Base 36 radix is used. The message space can only contain the following
/// characters: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".
const RADIX: u32 = 36;

/// The bit range for generating a random number.
const BIT_RANGE: usize = 256;

/// Generates a secret (BigUint) as 256 bits.
fn generate_secret() -> BigUint {
    rand::thread_rng().gen_biguint(BIT_RANGE)
}

/// Encrypts a given a message (bytes) and a secret used as the cipher.
fn encrypt_message(message: &[u8], secret: &BigUint) -> String {
    big_uint_to_str(encrypt(bytes_to_biguint(message), secret))
}

// Internal helper function, converts a biguint to a string.
fn big_uint_to_str(message: BigUint) -> String {
    message.to_str_radix(RADIX)
}

// Internal helper function, encrypts a message given a secret. Since this is a
// simple XOR, encryption and decryption are the same.
fn encrypt(message: BigUint, secret: &BigUint) -> BigUint {
    message ^ secret
}

// Internal helper function, parses a message to a BigUint.
fn bytes_to_biguint(message: &[u8]) -> BigUint {
    BigUint::parse_bytes(message, RADIX).expect("failed to parse message while encrypting")
}

/// Decrypts a given cipher text (bytes) and a secret.
//  DEV NOTES(ccdle12):
//  Has the same implemenation as `encrypt_message` but for clarity the function
//  has a different name.
fn decrypt_message(cipher_text: &[u8], secret: &BigUint) -> String {
    big_uint_to_str(encrypt(bytes_to_biguint(cipher_text), secret))
}

// fn encrypt_message(message: String, secret: BigInt)
#[cfg(test)]
mod test {
    use super::*;
    use num_traits::FromPrimitive;
    use num_traits::Zero;

    #[test]
    fn simple() {
        assert!(2 + 2 == 4);
    }

    #[test]
    fn simple_fail() {
        assert!(2 + 2 != 1);
    }

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
        let secret = generate_secret();
        let message = "attack";

        // Alice encrypts the messages with the secret.
        let cipher_text = encrypt_message(message.as_bytes(), &secret);
        println!("Encrypted message: {:?}", cipher_text);

        // Alice sends the cipher text on an insecure channel to Bob.
        // Bob receives it and recovers the plaintext.
        let decrypted_message = decrypt_message(cipher_text.as_bytes(), &secret);
        println!("Decrypted message: {:?}", decrypted_message);
        assert!(decrypted_message == "attack");

        // Eve intercepts the message and attempts to break the cipher.
        // For brevity, we will limit the exhausitve search.
        for i in 0..1000 {
            let secret_guess = BigUint::from_u32(i).unwrap();
            if message == decrypt_message(cipher_text.as_bytes(), &secret_guess) {
                panic!();
            }
        }
    }
}
