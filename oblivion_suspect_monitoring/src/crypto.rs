// Copyright © 1337_TECH, July 2025. All rights reserved.
// Provided "AS IS", without warranty of any kind, express or implied.
// Use at your own risk — the authors are not liable for any damages or losses.
// Built for research, experimentation, and security-conscious development.



use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or use openssl
use aes_gcm::aead::{Aead, NewAead};
use rand::RngCore;
use zstd::stream::encode_all;
use std::fs;

pub fn encrypt_and_compress_bundle(data: &[u8]) -> Vec<u8> {
    let compressed = encode_all(data, 3).unwrap();
    let key_bytes = fs::read("aes.key").unwrap_or_else(|_| {
        let mut kb = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut kb);
        fs::write("aes.key", &kb).unwrap();
        kb.to_vec()
    });

    let key = Key::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, compressed.as_ref()).unwrap();
    [&nonce_bytes[..], &ciphertext[..]].concat()
}
