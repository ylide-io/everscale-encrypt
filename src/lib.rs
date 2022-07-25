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
pub fn generate_ephemeral(recipient_public: &str) -> String {
    let ephemeral_keys = ed25519::KeyPair::generate(&mut rand::thread_rng());

    let recipient_public_key_bytes: [u8; 32] = convert_to_array(hex::decode(recipient_public).unwrap());
    let recipient_public_key = ed25519::PublicKey::from_bytes(recipient_public_key_bytes).unwrap();

    let shared_secret = ephemeral_keys.compute_shared_secret(&recipient_public_key);
    let sender_public_key_bytes = ephemeral_keys.public_key.to_bytes();

    let mut result_string: String = hex::encode(&sender_public_key_bytes).to_owned();
    result_string.push_str(&hex::encode(&shared_secret).to_owned());

    return result_string;
}

#[wasm_bindgen]
pub fn encrypt(raw_message: &str, raw_key: &str, raw_nonce: &str) -> String {
    let message_bytes = hex::decode(raw_message).unwrap();
    let key_bytes = hex::decode(raw_key).unwrap();
    let nonce_bytes = hex::decode(raw_nonce).unwrap();

    let key = Key::from_slice(&key_bytes); // 32-bytes
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = Nonce::from_slice(&nonce_bytes); // 12-bytes; unique per message

    let message_bytes_arr: &[u8] = &message_bytes;

    let ciphertext = cipher.encrypt(nonce, message_bytes_arr).expect("encryption failure!");

    return hex::encode(&ciphertext);
}