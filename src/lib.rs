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