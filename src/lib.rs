extern crate rand;

use wasm_bindgen::prelude::*;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use everscale_crypto::ed25519;

fn convert_to_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}

#[wasm_bindgen]
pub fn generate_ephemeral() -> String {
    let secret_key = ed25519::SecretKey::generate(&mut rand::thread_rng());
    return hex::encode(&secret_key.to_bytes());
}

#[wasm_bindgen]
pub fn get_public_key(secret_key_hex: &str) -> String {
    let secret_key_bytes: [u8; 32] = convert_to_array(hex::decode(secret_key_hex).unwrap());
    let secret_key = ed25519::SecretKey::from_bytes(secret_key_bytes);
    let public_key = ed25519::PublicKey::from(&secret_key);
    return hex::encode(&public_key.to_bytes());
}

#[wasm_bindgen]
pub fn encrypt(secret_key_hex: &str, recipient_public_hex: &str, raw_data: &str, raw_nonce: &str) -> String {
    let secret_key_bytes: [u8; 32] = convert_to_array(hex::decode(secret_key_hex).unwrap());
    let ephemeral_keys = ed25519::KeyPair::from(&ed25519::SecretKey::from_bytes(secret_key_bytes));
    
    let recipient_public_key_bytes: [u8; 32] = convert_to_array(hex::decode(recipient_public_hex).unwrap());
    let recipient_public_key = ed25519::PublicKey::from_bytes(recipient_public_key_bytes).unwrap();

    let shared_secret = ephemeral_keys.compute_shared_secret(&recipient_public_key);

    let data_bytes = hex::decode(raw_data).unwrap();
    let nonce_bytes = hex::decode(raw_nonce).unwrap();

    let key = Key::from_slice(&shared_secret); // 32-bytes
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = Nonce::from_slice(&nonce_bytes); // 12-bytes; unique per message

    let data_bytes_arr: &[u8] = &data_bytes;

    let ciphertext = cipher.encrypt(nonce, data_bytes_arr).expect("encryption failure!");

    return hex::encode(&ciphertext);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let secret_hex = "a84462ec64db0c5a1d4b3b77f70b5c1ee2fe753b95eccd1302b7e7cd03d24640";
        let recipient_secret = "96f14d2c755ddfe9ea7ff911a1d0b5f22327d503ef8c2ebdbfff3c22232dd45b";
        let public_recipient = get_public_key(recipient_secret);
        assert_eq!("2f8a8dfa4d60c05c27bcd1852e28da10f7d509e4851a6f83002606e6762a99d9", public_recipient);
        let message = "Hello, world!";
        let message_hex = hex::encode(message);

        let nonce = "111111111111111111111111";
        let nonce_bytes = hex::decode(nonce).unwrap();

        let encrypted_message_hex = encrypt(
            secret_hex,
            public_recipient.as_str(),
            message_hex.as_str(),
            nonce,
        );
        assert_eq!("6da85e22b9b67af048adab7ed21f279e2dcccadac1424c48f38939eb49", encrypted_message_hex);
        let encrypted_message = hex::decode(encrypted_message_hex).unwrap();

        let decipher = decipher(
            recipient_secret,
            get_public_key(secret_hex).as_str(),
        );

        let decrypted_by_recipient_message_bytes = decipher.decrypt(Nonce::from_slice(nonce_bytes.as_slice()), encrypted_message.as_slice()).unwrap();

        assert_eq!(String::from_utf8(decrypted_by_recipient_message_bytes).unwrap(), message);
    }

    fn decipher(recipient_secret: &str, sender_public: &str) -> ChaCha20Poly1305 {
        let secret_key_bytes = convert_to_array(hex::decode(recipient_secret).unwrap());
        let ephemeral_keys = ed25519::KeyPair::from(&ed25519::SecretKey::from_bytes(secret_key_bytes));

        let sender_public_key_bytes = convert_to_array(hex::decode(sender_public).unwrap());
        let sender_public_key = ed25519::PublicKey::from_bytes(sender_public_key_bytes).unwrap();

        let shared_secret = ephemeral_keys.compute_shared_secret(&sender_public_key);

        let key = Key::from_slice(&shared_secret); // 32-bytes
        ChaCha20Poly1305::new(key)
    }
}
