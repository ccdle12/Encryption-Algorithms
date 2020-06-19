/// ```
/// m = plaintext message
/// c = ciphertext message
/// Ke = A secret key
/// m = E(Ke, m) = Encryption function of a secret and message
/// m = D(Ke, c) = Decryption function of a cipher text given the secret
/// ```
///
/// It is assumed the secret is shared securely.
/// Both parties use the secret key to encrypt and decrypt messages.
/// A good encryption function makes it impossible to find `m` given `c`.

/// ```
///                           Eve
///                            |
///                            |  m = D(?, c)
///                            |
///                            V
///     Alice                  c                   Bob
/// c = E(Ke, m)     -------------------->     m = D(Ke, c)
/// ```

#[cfg(test)]
mod test {
    use crypto_kit::xor_cipher::{decrypt_message, encrypt_message, generate_secret};

    #[test]
    fn basic_xor_cipher() {
        // Alice and Bob are communicating with a shared secret (large random
        // number). Eve is attempting to read the message.
        let secret = generate_secret();
        let message = "attack";

        // Alice encrypts the messages with the secret.
        let cipher_text = encrypt_message(message.as_bytes(), &secret);

        // Alice sends the cipher text on an insecure channel to Bob.
        // Bob receives it and recovers the plaintext.
        let decrypted_message = decrypt_message(cipher_text.as_bytes(), &secret);
        assert!(decrypted_message == "attack");
    }
}
