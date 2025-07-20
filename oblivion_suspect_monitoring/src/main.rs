// Copyright © 1337_TECH, July 2025. All rights reserved.
// Provided "AS IS", without warranty of any kind, express or implied.
// Use at your own risk — the authors are not liable for any damages or losses.
// Built for research, experimentation, and security-conscious development.



mod crypto;
mod packet_pipe;
mod patterns;

use std::fs::{File, create_dir_all};
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::PathBuf;
use patterns::{PATTERN_IKEV2, PATTERN_FILEUPLOAD};

fn now_ts() -> String {
    let start = SystemTime::now();
    let since_epoch = start.duration_since(UNIX_EPOCH).unwrap();
    let t = chrono::NaiveDateTime::from_timestamp_opt(
        since_epoch.as_secs() as i64, 0).unwrap();
    t.format("%Y%m%d_%H%M%S").to_string()
}

fn main() {
    let packets = packet_pipe::read_suspect_packets("/dev/suspect_kmod");

    for pkt in packets {
        if pkt.windows(PATTERN_IKEV2.len()).any(|w| w == PATTERN_IKEV2)
            || pkt.windows(PATTERN_FILEUPLOAD.len()).any(|w| w == PATTERN_FILEUPLOAD) {

            let ts = now_ts();
            let outdir = PathBuf::from(format!("output/{}", ts));
            create_dir_all(&outdir).unwrap();

            std::fs::write(outdir.join("payload.bin"), &pkt).unwrap();

            let metadata = format!("{{"ts":"{}","match":"Cisco CVE pattern"}}", ts);
            std::fs::write(outdir.join("metadata.json"), metadata).unwrap();

            let bundle = [&pkt[..], metadata.as_bytes()].concat();
            let encrypted = crypto::encrypt_and_compress_bundle(&bundle);
            std::fs::write(outdir.join("capture.enc.zst"), &encrypted).unwrap();
        }
    }
}
