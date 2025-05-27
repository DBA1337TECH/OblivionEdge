use openssl::x509::X509;
use openssl::pkey::PKey;
use openssl::hash::{MessageDigest, Hasher};
use std::fs;
use hex;

pub fn verify_cert_hash(cert_path: &str, hash_file_path: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let cert_bytes = fs::read(cert_path)?;
    let cert = X509::from_pem(&cert_bytes)?;
    let pubkey: PKey<_> = cert.public_key()?;

    let pubkey_der = pubkey.public_key_to_der()?;
    let mut hasher = Hasher::new(MessageDigest::sha512())?;
    hasher.update(&pubkey_der)?;
    let digest = hasher.finish()?;

    let stored_hash = fs::read_to_string(hash_file_path)?;
    let expected = stored_hash.split_whitespace().next().unwrap_or("");
    let actual_hex = hex::encode(digest);

    Ok(actual_hex == expected)
}
