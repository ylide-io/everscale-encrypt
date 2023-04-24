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

fn cipher(secret_key_hex: &str, recipient_public_hex: &str) -> ChaCha20Poly1305 {
    let ephemeral_keys = ed25519::KeyPair::from(&secret_key_from_hex(secret_key_hex));
    let recipient_public_key = public_key_from_hex(recipient_public_hex);
    let shared_secret = ephemeral_keys.compute_shared_secret(&recipient_public_key);
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
