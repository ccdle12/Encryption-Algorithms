#[cfg(test)]
mod test {
    use crypto_kit::XORCipher;

    #[test]
    fn basic_xor_cipher() {
        let xor_cipher = XORCipher::new();

        // Alice and Bob are communicating with a shared secret (large random
        // number). Eve is attempting to read the message.
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
        assert!(
            xor_cipher.exhaustive_search(
                &String::from(message),
                &String::from(cipher_text),
                0,
                1000
            ) == false
        )
    }
}
