extern crate rand;

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use everscale_crypto::ed25519;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn generate_ephemeral() -> String {
    let secret_key = ed25519::SecretKey::generate(&mut rand::thread_rng());
    hex::encode(secret_key.to_bytes())
}

#[wasm_bindgen]
pub fn get_public_key(secret_key_hex: &str) -> String {
    let secret_key = secret_key_from_hex(secret_key_hex);
    let public_key = ed25519::PublicKey::from(&secret_key);
    hex::encode(public_key.to_bytes())
}

#[wasm_bindgen]
pub fn encrypt(
    secret_key_hex: &str,
    recipient_public_hex: &str,
    raw_data: &str,
    raw_nonce: &str,
) -> String {
    let data_bytes = hex::decode(raw_data).unwrap();

    let nonce = nonce_from_hex(raw_nonce); // 12-bytes; unique per message
    let cipher = cipher(secret_key_hex, recipient_public_hex);

    let ciphertext = cipher
        .encrypt(&nonce, data_bytes.as_slice())
        .expect("encryption failure!");

    hex::encode(ciphertext)
}

fn cipher(user_secret_key: &str, other_side_public_key: &str) -> ChaCha20Poly1305 {
    let ephemeral_keys = ed25519::KeyPair::from(&secret_key_from_hex(user_secret_key));
    let other_side_public_key = public_key_from_hex(other_side_public_key);
    let shared_secret = ephemeral_keys.compute_shared_secret(&other_side_public_key);
    let key = Key::from(shared_secret); // 32-bytes

    ChaCha20Poly1305::new(&key)
}

fn secret_key_from_hex(hex: &str) -> ed25519::SecretKey {
    let secret_key_bytes = convert_to_array(hex::decode(hex).unwrap());
    ed25519::SecretKey::from_bytes(secret_key_bytes)
}

fn nonce_from_hex(hex: &str) -> Nonce {
    let hex_bytes = convert_to_array(hex::decode(hex).unwrap());
    Nonce::from(hex_bytes)
}

fn public_key_from_hex(hex: &str) -> ed25519::PublicKey {
    let secret_key_bytes = convert_to_array(hex::decode(hex).unwrap());
    ed25519::PublicKey::from_bytes(secret_key_bytes).unwrap()
}

fn convert_to_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    match v.try_into() {
        Ok(array) => array,
        Err(v) => panic!("Expected a Vec of length {} but it was {}", N, v.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let secret_hex = "a84462ec64db0c5a1d4b3b77f70b5c1ee2fe753b95eccd1302b7e7cd03d24640";
        let recipient_secret = "96f14d2c755ddfe9ea7ff911a1d0b5f22327d503ef8c2ebdbfff3c22232dd45b";
        let public_recipient = get_public_key(recipient_secret);
        assert_eq!(
            "2f8a8dfa4d60c05c27bcd1852e28da10f7d509e4851a6f83002606e6762a99d9",
            public_recipient
        );
        let message = "Hello, world!";
        let message_hex = hex::encode(message);

        let nonce_hex = "111111111111111111111111";

        let encrypted_message_hex = encrypt(
            secret_hex,
            public_recipient.as_str(),
            message_hex.as_str(),
            nonce_hex,
        );
        assert_eq!(
            "6da85e22b9b67af048adab7ed21f279e2dcccadac1424c48f38939eb49",
            encrypted_message_hex
        );
        let encrypted_message = hex::decode(encrypted_message_hex).unwrap();

        let cipher = cipher(recipient_secret, get_public_key(secret_hex).as_str());

        let decrypted_by_recipient_message_bytes = cipher
            .decrypt(
                &nonce_from_hex(nonce_hex),
                encrypted_message.as_slice(),
            )
            .unwrap();

        assert_eq!(
            String::from_utf8(decrypted_by_recipient_message_bytes).unwrap(),
            message
        );
    }
}
