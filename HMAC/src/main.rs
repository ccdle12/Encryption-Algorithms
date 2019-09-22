/// ```
/// Message Encryption:
/// m = plaintext message
/// c = ciphertext message
/// Ke = Encryption secret key
/// m = E(Ke, m) = Encryption function of a secret and message
/// m = D(Ke, c) = Decryption function of a cipher text given the secret
///
/// Message Authentication:
/// a = authentication hash
/// Ka = Message Authentication secret key
/// H = message auth hashing function
/// ```
///
/// It is assumed the secret is shared securely.
/// Both parties use the secret key to encrypt and decrypt messages.
/// A good encryption function makes it impossible to find `m` given `c`.
///
/// Alice creates the cipher text and message authnetication hash
/// (from the plaintext?).
///
/// Bob decrypts the message and calculates the authenticaion hash according
/// to the decrypted message. If the generated hash matches the one received
/// then the message has not been tampered.

/// ```
///                           Eve
///                            |
///                            |  m = D(?, c)
///                            |
///                            V
///     Alice                 c, a                   Bob
/// c = E(Ke, m)     -------------------->       m = D(Ke, c)
/// a = H(Ka, m)                                 a = H(Ka, m)
/// ```

#[cfg(test)]
mod tests {
    use crypto_kit::xor_cipher::{decrypt_message, encrypt_message, generate_secret};
    use crypto_kit::HMAC;

    #[test]
    fn it_works() {
        // Ke and Ka (secrets) are generated.
        let encryption_secret = generate_secret();
        let auth_secret = generate_secret();

        // Alice and Bob share the secret on a secure channel.
        let alice_hmac = HMAC::from_existing_secret(auth_secret.clone());
        let bob_hmac = HMAC::from_existing_secret(auth_secret.clone());

        // Alice sends Bob a message. She encrypts the message and generates
        // an authentication hash.
        let message = String::from("attack");
        let cipher_text: String = encrypt_message(&message.as_bytes(), &encryption_secret);
        let auth_hash: Vec<u8> = alice_hmac.generate_auth(&message.as_bytes());

        // Bob Receives the message and decrypts as well as verifying the auth
        // of the plaintext.
        let plain_text: String = decrypt_message(&cipher_text.as_bytes(), &encryption_secret);
        assert_eq!(&plain_text, &message);
        assert_eq!(bob_hmac.check_auth(&message.as_bytes(), &auth_hash), true);

        // In this scenario for simplicity, Eve intercepts the same message sent
        // a second time. This time she has access to the encryption_secret, and
        // changes the message.
        //
        // She will try her luck, using Ke (encryption_secret) as the Ka
        // (auth_secret), to regenerate an auth.
        let eve_hmac = HMAC::from_existing_secret(encryption_secret.clone());
        assert_eq!(
            &message,
            &decrypt_message(&cipher_text.as_bytes(), &encryption_secret)
        );
        let eves_message = String::from("retreat");
        let eves_cipher_text: String =
            encrypt_message(&eves_message.as_bytes(), &encryption_secret);

        // Scenario 1. Eve sends the altered message without changing the auth.
        assert_eq!(
            bob_hmac.check_auth(&eves_message.as_bytes(), &auth_hash),
            false
        );

        // Scenarion 2. Eve tries her luck by using the encryption secret as the
        // auth secret.
        // This should fail since, Bob is using Ka for auth hashing and Eve is
        // trying Ke.
        let eves_auth_hash: Vec<u8> = eve_hmac.generate_auth(&eves_message.as_bytes());
        assert_eq!(
            bob_hmac.check_auth(&eves_message.as_bytes(), &auth_hash),
            false
        );
    }
}
