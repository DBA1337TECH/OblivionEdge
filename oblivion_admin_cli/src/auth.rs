use std::fs;

/// Replace with actual TPM-based token generation
pub fn get_auth_token() -> u32 {
    // Temporary static secret — replace with TPM fetch
    const PATH: &str = "/etc/oblivion/ztna_secret.key";

    fs::read(PATH)
        .ok()
        .and_then(|b| b.get(..4).map(|s| u32::from_ne_bytes([s[0], s[1], s[2], s[3]])))
        .unwrap_or(0xdeadbeef)
}

